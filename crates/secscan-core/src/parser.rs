use tree_sitter::{Parser, Tree};

pub struct PythonParser {
    parser: Parser,
}

impl PythonParser {
    pub fn new() -> Result<Self, String> {
        let mut parser = Parser::new();
        let language = tree_sitter_python::language();
        parser
            .set_language(language)
            .map_err(|e| format!("Failed to set Python language for tree-sitter: {:?}", e))?;
        Ok(Self { parser })
    }

    pub fn parse(&mut self, source_code: &str) -> Option<Tree> {
        self.parser.parse(source_code, None)
    }
}
