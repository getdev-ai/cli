//! tree-sitter grammar dependencies re-exported behind one crate boundary.
//!
//! Isolating the grammar crates here keeps the slow-compiling C dependencies
//! in one cached unit and confines all FFI to a single reviewed crate — every
//! other workspace crate forbids `unsafe_code`.

pub use tree_sitter;

use tree_sitter::Language;

pub fn javascript() -> Language {
    tree_sitter_javascript::LANGUAGE.into()
}

pub fn typescript() -> Language {
    tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()
}

pub fn tsx() -> Language {
    tree_sitter_typescript::LANGUAGE_TSX.into()
}

pub fn python() -> Language {
    tree_sitter_python::LANGUAGE.into()
}
