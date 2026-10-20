use crate::models::{DataFlowStep, Finding, Severity};
use std::collections::HashMap;
use tree_sitter::{Node, Tree};
use uuid::Uuid;

pub struct TaintAnalyzer<'a> {
    source_code: &'a str,
    file_path: &'a str,
    lines: Vec<&'a str>,
}

impl<'a> TaintAnalyzer<'a> {
    pub fn new(source_code: &'a str, file_path: &'a str) -> Self {
        let lines = source_code.lines().collect();
        Self {
            source_code,
            file_path,
            lines,
        }
    }

    fn get_node_text(&self, node: Node) -> &'a str {
        &self.source_code[node.start_byte()..node.end_byte()]
    }

    fn get_line_snippet(&self, line_num: usize) -> String {
        if line_num > 0 && line_num <= self.lines.len() {
            self.lines[line_num - 1].trim().to_string()
        } else {
            String::new()
        }
    }

    pub fn analyze(&self, tree: &Tree) -> Vec<Finding> {
        let mut findings = Vec::new();
        let root = tree.root_node();
        let framework = self.detect_framework();

        self.traverse_for_functions(root, &framework, &mut findings);
        findings
    }

    fn detect_framework(&self) -> String {
        if self.source_code.contains("flask") || self.source_code.contains("Flask") {
            "Flask (sqlite3/SQLAlchemy)".to_string()
        } else if self.source_code.contains("django") || self.source_code.contains("Django") {
            "Django ORM".to_string()
        } else if self.source_code.contains("fastapi") || self.source_code.contains("FastAPI") {
            "FastAPI".to_string()
        } else {
            "Standard Python".to_string()
        }
    }

    fn traverse_for_functions(&self, node: Node, framework: &str, findings: &mut Vec<Finding>) {
        if node.kind() == "function_definition" {
            self.analyze_function(node, framework, findings);
        }

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.traverse_for_functions(child, framework, findings);
        }
    }

    fn analyze_function(&self, func_node: Node, framework: &str, findings: &mut Vec<Finding>) {
        // Taint Map: Variable Name -> List of DataFlowStep (provenance)
        let mut tainted_vars: HashMap<String, Vec<DataFlowStep>> = HashMap::new();
        self.walk_statements(func_node, &mut tainted_vars, framework, findings);
    }

    fn walk_statements(
        &self,
        node: Node,
        tainted_vars: &mut HashMap<String, Vec<DataFlowStep>>,
        framework: &str,
        findings: &mut Vec<Finding>,
    ) {
        let kind = node.kind();

        if kind == "assignment" {
            self.handle_assignment(node, tainted_vars);
        } else if kind == "call" {
            self.check_sink_call(node, tainted_vars, framework, findings);
        } else if kind == "expression_statement" {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                self.walk_statements(child, tainted_vars, framework, findings);
            }
            return;
        } else if kind == "with_statement" {
            self.check_with_open(node, tainted_vars, framework, findings);
        }

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() != "function_definition" {
                self.walk_statements(child, tainted_vars, framework, findings);
            }
        }
    }

    fn handle_assignment(&self, assign_node: Node, tainted_vars: &mut HashMap<String, Vec<DataFlowStep>>) {
        let left = assign_node.child_by_field_name("left");
        let right = assign_node.child_by_field_name("right");

        if let (Some(left_node), Some(right_node)) = (left, right) {
            let var_name = self.get_node_text(left_node).trim().to_string();
            let right_text = self.get_node_text(right_node);
            let line = right_node.start_position().row + 1;
            let col = right_node.start_position().column + 1;

            // SANITIZATION CHECK 1: os.path.basename strips directory traversal
            if right_text.contains("os.path.basename") || right_text.contains(".name") {
                // Not tainted for path traversal
                return;
            }

            // Check if right side directly introduces a Source
            if self.is_taint_source(right_text) {
                let step = DataFlowStep {
                    step_index: 0,
                    label: "SOURCE".to_string(),
                    variable: var_name.clone(),
                    line,
                    column: col,
                    description: format!("User-controlled HTTP input received via '{}'", right_text),
                };
                tainted_vars.insert(var_name, vec![step]);
                return;
            }

            // Check if right side propagates existing tainted variables
            let mut matched_taints = Vec::new();
            for (tainted_var, steps) in tainted_vars.iter() {
                if self.expression_references_var(right_node, tainted_var) {
                    matched_taints.extend(steps.clone());
                }
            }

            if !matched_taints.is_empty() {
                let next_idx = matched_taints.len();
                let prop_step = DataFlowStep {
                    step_index: next_idx,
                    label: "PROPAGATION".to_string(),
                    variable: var_name.clone(),
                    line,
                    column: col,
                    description: format!("Tainted data assigned or interpolated into '{}'", var_name),
                };
                matched_taints.push(prop_step);
                tainted_vars.insert(var_name, matched_taints);
            }
        }
    }

    fn is_taint_source(&self, text: &str) -> bool {
        text.contains("request.args")
            || text.contains("request.form")
            || text.contains("request.values")
            || text.contains("request.GET")
            || text.contains("request.POST")
            || text.contains("request.get_json")
            || text.contains("request.json")
            || text.contains("sys.argv")
            || text.contains("input(")
    }

    fn expression_references_var(&self, expr_node: Node, var_name: &str) -> bool {
        // True AST/CST check: Walk node children and find if an 'identifier' node matches var_name
        if expr_node.kind() == "identifier" {
            return self.get_node_text(expr_node) == var_name;
        }

        let mut cursor = expr_node.walk();
        for child in expr_node.children(&mut cursor) {
            if self.expression_references_var(child, var_name) {
                return true;
            }
        }
        false
    }

    fn check_sink_call(
        &self,
        call_node: Node,
        tainted_vars: &HashMap<String, Vec<DataFlowStep>>,
        framework: &str,
        findings: &mut Vec<Finding>,
    ) {
        let function_node = match call_node.child_by_field_name("function") {
            Some(f) => f,
            None => return,
        };

        let func_call_str = self.get_node_text(function_node);
        let args_node = match call_node.child_by_field_name("arguments") {
            Some(a) => a,
            None => return,
        };
        let line = call_node.start_position().row + 1;
        let col = call_node.start_position().column + 1;

        // 1. Check SQL Sinks: .execute(...) / .executemany(...)
        if func_call_str.ends_with(".execute") || func_call_str.ends_with(".executemany") {
            // In Python DB-API: cursor.execute(query_string, [params...])
            // The query string is the FIRST positional argument!
            let mut cursor = args_node.walk();
            let mut positional_args = Vec::new();
            for child in args_node.children(&mut cursor) {
                if child.kind() != "(" && child.kind() != ")" && child.kind() != "," {
                    positional_args.push(child);
                }
            }

            if let Some(first_arg) = positional_args.first() {
                let first_arg_text = self.get_node_text(*first_arg);

                // Only flag if the FIRST argument (the query string itself) contains or is a tainted variable!
                for (tainted_var, steps) in tainted_vars {
                    if self.expression_references_var(*first_arg, tainted_var) {
                        // If it's a static literal, it's safe (e.g. "SELECT ... WHERE x = ?")
                        if first_arg.kind() == "string" {
                            continue;
                        }

                        let mut flow = steps.clone();
                        let sink_step = DataFlowStep {
                            step_index: flow.len(),
                            label: "SINK".to_string(),
                            variable: tainted_var.clone(),
                            line,
                            column: col,
                            description: format!("Unsanitized tainted query passed to SQL execution '{}'", func_call_str),
                        };

                        let source_step = flow.first().cloned();
                        let prop_steps = if flow.len() > 1 {
                            flow[1..].to_vec()
                        } else {
                            vec![]
                        };

                        findings.push(Finding {
                            id: format!("SEC-001-{}", Uuid::new_v4().to_string()[..8].to_uppercase()),
                            rule_id: "SEC-001".to_string(),
                            rule_name: "SQL Injection".to_string(),
                            severity: Severity::High,
                            confidence: 0.95,
                            file_path: self.file_path.to_string(),
                            line,
                            column: col,
                            source: source_step,
                            propagation: prop_steps,
                            sink: Some(sink_step),
                            code_snippet: self.get_line_snippet(line),
                            recommended_fix: "Use parameterized queries with placeholder syntax (e.g. '?' or '%s') instead of string formatting.".to_string(),
                            target_framework: framework.to_string(),
                        });
                        break;
                    }
                }
            }
        }

        // 2. Check Command Injection Sinks: subprocess.* or os.system
        if func_call_str.contains("subprocess.check_output")
            || func_call_str.contains("subprocess.run")
            || func_call_str.contains("subprocess.Popen")
            || func_call_str.contains("os.system")
            || func_call_str.contains("os.popen")
        {
            let args_text = self.get_node_text(args_node);

            // SANITIZATION CHECK 2: If shell=False and command is a list, it is SAFE from shell injection!
            let is_shell_true = args_text.contains("shell=True");
            let is_os_system = func_call_str.contains("os.system") || func_call_str.contains("os.popen");

            if is_shell_true || is_os_system {
                for (tainted_var, steps) in tainted_vars {
                    if self.expression_references_var(args_node, tainted_var) {
                        let mut flow = steps.clone();
                        let sink_step = DataFlowStep {
                            step_index: flow.len(),
                            label: "SINK".to_string(),
                            variable: tainted_var.clone(),
                            line,
                            column: col,
                            description: format!("Tainted input passed into shell command executor with shell evaluation enabled '{}'", func_call_str),
                        };

                        let source_step = flow.first().cloned();
                        let prop_steps = if flow.len() > 1 {
                            flow[1..].to_vec()
                        } else {
                            vec![]
                        };

                        findings.push(Finding {
                            id: format!("SEC-002-{}", Uuid::new_v4().to_string()[..8].to_uppercase()),
                            rule_id: "SEC-002".to_string(),
                            rule_name: "Command Injection".to_string(),
                            severity: Severity::Critical,
                            confidence: 0.96,
                            file_path: self.file_path.to_string(),
                            line,
                            column: col,
                            source: source_step,
                            propagation: prop_steps,
                            sink: Some(sink_step),
                            code_snippet: self.get_line_snippet(line),
                            recommended_fix: "Pass arguments as a safe list with shell=False, avoiding dynamic string shell evaluation.".to_string(),
                            target_framework: framework.to_string(),
                        });
                        break;
                    }
                }
            }
        }
    }

    fn check_with_open(
        &self,
        with_node: Node,
        tainted_vars: &HashMap<String, Vec<DataFlowStep>>,
        framework: &str,
        findings: &mut Vec<Finding>,
    ) {
        let with_text = self.get_node_text(with_node);
        let line = with_node.start_position().row + 1;
        let col = with_node.start_position().column + 1;

        if with_text.contains("open(") {
            for (tainted_var, steps) in tainted_vars {
                let re = regex::Regex::new(&format!(r"open\([^)]*\b{}\b", regex::escape(tainted_var))).unwrap();
                if re.is_match(with_text) {
                    let mut flow = steps.clone();
                    let sink_step = DataFlowStep {
                        step_index: flow.len(),
                        label: "SINK".to_string(),
                        variable: tainted_var.clone(),
                        line,
                        column: col,
                        description: "Tainted user path passed to filesystem open() without basename sanitization".to_string(),
                    };

                    let source_step = flow.first().cloned();
                    let prop_steps = if flow.len() > 1 {
                        flow[1..].to_vec()
                    } else {
                        vec![]
                    };

                    findings.push(Finding {
                        id: format!("SEC-003-{}", Uuid::new_v4().to_string()[..8].to_uppercase()),
                        rule_id: "SEC-003".to_string(),
                        rule_name: "Path Traversal".to_string(),
                        severity: Severity::High,
                        confidence: 0.92,
                        file_path: self.file_path.to_string(),
                        line,
                        column: col,
                        source: source_step,
                        propagation: prop_steps,
                        sink: Some(sink_step),
                        code_snippet: self.get_line_snippet(line),
                        recommended_fix: "Sanitize paths using os.path.basename() or resolve and verify within an allowed directory boundary.".to_string(),
                        target_framework: framework.to_string(),
                    });
                    break;
                }
            }
        }
    }
}
