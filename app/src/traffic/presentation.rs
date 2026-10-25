//! Bounded, worker-side formatting/highlighting; only visible lines are laid out by egui.
use eframe::egui::{self, Color32, FontId, TextFormat, text::LayoutJob};
use egui_theme_kit::Tokens;
use std::{borrow::Cow, path::Path, sync::LazyLock};
use syntect::{
    easy::HighlightLines,
    highlighting::{Color, StyleModifier, Theme, ThemeItem},
    parsing::SyntaxSet,
    util::LinesWithEndings,
};

static SYNTAXES: LazyLock<SyntaxSet> = LazyLock::new(SyntaxSet::load_defaults_newlines);
pub(super) const FORMAT_INPUT_LIMIT: usize = 2 * 1024 * 1024;
pub(super) const FORMAT_OUTPUT_LIMIT: usize = 8 * 1024 * 1024;
// Virtualizing lines alone does not bound layout cost for a multi-megabyte string literal.
const DISPLAY_LINE_BYTES: usize = 2048;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Language {
    Json,
    Html,
    JavaScript,
    TypeScript,
    Css,
    Xml,
    Text,
}

impl Language {
    pub fn detect(mime: &str, url: &str) -> Self {
        let mime = mime
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        if mime.ends_with("/json") || mime.ends_with("+json") {
            return Self::Json;
        }
        match mime.as_str() {
            "text/html" | "application/xhtml+xml" => return Self::Html,
            "text/javascript"
            | "application/javascript"
            | "application/x-javascript"
            | "text/ecmascript"
            | "application/ecmascript" => return Self::JavaScript,
            "text/typescript" | "application/typescript" => return Self::TypeScript,
            "text/css" => return Self::Css,
            "text/xml" | "application/xml" => return Self::Xml,
            _ if mime.ends_with("+xml") => return Self::Xml,
            _ => {}
        }
        // An explicit content type wins over a misleading URL suffix.
        if !matches!(
            mime.as_str(),
            "" | "text/plain" | "application/octet-stream"
        ) {
            return Self::Text;
        }
        let path = url
            .split(['?', '#'])
            .next()
            .unwrap_or(url)
            .to_ascii_lowercase();
        match path.rsplit('.').next().unwrap_or_default() {
            "json" | "map" => Self::Json,
            "html" | "htm" => Self::Html,
            "js" | "mjs" | "cjs" | "jsx" => Self::JavaScript,
            "ts" | "tsx" => Self::TypeScript,
            "css" => Self::Css,
            "xml" | "svg" => Self::Xml,
            _ => Self::Text,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Json => "JSON",
            Self::Html => "HTML",
            Self::JavaScript => "JavaScript",
            Self::TypeScript => "TypeScript",
            Self::Css => "CSS",
            Self::Xml => "XML",
            Self::Text => "Text",
        }
    }

    fn extension(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Html => "html",
            Self::JavaScript | Self::TypeScript => "js",
            Self::Css => "css",
            Self::Xml => "xml",
            Self::Text => "txt",
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
pub(super) struct Palette {
    colors: [Color32; 9],
    size: f32,
}

impl Palette {
    pub fn from_ui(ui: &egui::Ui) -> Self {
        let t = Tokens::get(ui.ctx());
        Self {
            colors: [
                t.text,
                t.text_dim,
                t.primary,
                t.success,
                t.secondary,
                t.tertiary,
                t.info,
                t.warn,
                t.error,
            ],
            size: egui::TextStyle::Monospace.resolve(ui.style()).size,
        }
    }

    fn format(self, color: Color32) -> TextFormat {
        TextFormat {
            font_id: FontId::monospace(self.size),
            color,
            ..Default::default()
        }
    }

    fn theme(self) -> Theme {
        let color = |c: Color32| Color {
            r: c.r(),
            g: c.g(),
            b: c.b(),
            a: c.a(),
        };
        let mut theme = Theme::default();
        theme.settings.foreground = Some(color(self.colors[0]));
        for (scope, index) in [
            ("comment", 1),
            ("punctuation", 1),
            ("keyword, storage", 2),
            ("string", 3),
            ("constant", 4),
            ("entity.name, entity.other.attribute-name", 5),
            ("support, variable", 6),
            ("keyword.operator", 7),
            ("invalid", 8),
        ] {
            theme.scopes.push(ThemeItem {
                scope: scope.parse().expect("static syntax selector"),
                style: StyleModifier {
                    foreground: Some(color(self.colors[index])),
                    ..Default::default()
                },
            });
        }
        theme
    }
}

pub(super) struct Code {
    pub text: String,
    lines: Vec<CodeLine>,
    spans: Vec<Span>,
    columns: usize,
    size: f32,
    wrapped: bool,
}

struct CodeLine {
    text: std::ops::Range<usize>,
    spans: std::ops::Range<usize>,
}
struct Span {
    text: std::ops::Range<usize>,
    color: Color32,
}

impl Code {
    pub fn highlight(text: String, language: Language, palette: Palette) -> Self {
        let theme = palette.theme();
        let syntax = SYNTAXES
            .find_syntax_by_extension(language.extension())
            .unwrap_or_else(|| SYNTAXES.find_syntax_plain_text());
        let mut highlighter = HighlightLines::new(syntax, &theme);
        let mut lines = Vec::new();
        let mut spans = Vec::new();
        let mut offset = 0;
        for line in LinesWithEndings::from(&text) {
            let first_span = spans.len();
            let end = offset + line.trim_end_matches(['\r', '\n']).len();
            let mut cursor = offset;
            match highlighter.highlight_line(line, &SYNTAXES) {
                Ok(ranges) => {
                    for (style, text) in ranges {
                        let c = style.foreground;
                        let next = (cursor + text.len()).min(end);
                        if cursor < next {
                            spans.push(Span {
                                text: cursor..next,
                                color: Color32::from_rgba_unmultiplied(c.r, c.g, c.b, c.a),
                            });
                        }
                        cursor = next;
                    }
                }
                Err(_) => spans.push(Span {
                    text: offset..end,
                    color: palette.colors[0],
                }),
            }
            lines.push(CodeLine {
                text: offset..end,
                spans: first_span..spans.len(),
            });
            offset += line.len();
        }
        Self::new(text, lines, spans, palette.size)
    }

    fn new(text: String, lines: Vec<CodeLine>, spans: Vec<Span>, size: f32) -> Self {
        let mut display_lines = Vec::new();
        let mut display_spans = Vec::new();
        let mut wrapped = false;
        for line in lines {
            let mut start = line.text.start;
            let mut span_index = line.spans.start;
            loop {
                let mut end = (start + DISPLAY_LINE_BYTES).min(line.text.end);
                while !text.is_char_boundary(end) {
                    end -= 1;
                }
                let first_span = display_spans.len();
                while span_index < line.spans.end {
                    let span = &spans[span_index];
                    if span.text.start >= end {
                        break;
                    }
                    display_spans.push(Span {
                        text: span.text.start.max(start)..span.text.end.min(end),
                        color: span.color,
                    });
                    if span.text.end > end {
                        break;
                    }
                    span_index += 1;
                }
                display_lines.push(CodeLine {
                    text: start..end,
                    spans: first_span..display_spans.len(),
                });
                if end == line.text.end {
                    break;
                }
                wrapped = true;
                start = end;
            }
        }
        let columns = display_lines
            .iter()
            .map(|line| {
                text[line.text.clone()]
                    .chars()
                    .map(|c| if c == '\t' { 4 } else { 1 })
                    .sum()
            })
            .max()
            .unwrap_or(1);
        Self {
            text,
            lines: display_lines,
            spans: display_spans,
            columns,
            size,
            wrapped,
        }
    }

    pub fn hex(bytes: &[u8], offset: u64, palette: Palette) -> Self {
        let mut text = String::new();
        let mut lines = Vec::new();
        let mut spans = Vec::new();
        for (row, chunk) in bytes.chunks(16).enumerate() {
            let mut job = LayoutJob::default();
            let mut append = |text: &str, index: usize| {
                job.append(text, 0., palette.format(palette.colors[index]))
            };
            append(&format!("{:08x}  ", offset + row as u64 * 16), 1);
            for i in 0..16 {
                if i == 8 {
                    append(" ", 1);
                }
                if let Some(&byte) = chunk.get(i) {
                    let index = if byte == 0 {
                        1
                    } else if byte.is_ascii_graphic() || byte == b' ' {
                        0
                    } else if byte.is_ascii_control() {
                        7
                    } else {
                        4
                    };
                    append(&format!("{byte:02x} "), index);
                } else {
                    append("   ", 1);
                }
            }
            append(" │", 1);
            for &byte in chunk {
                let printable = byte.is_ascii_graphic() || byte == b' ';
                append(
                    &if printable {
                        (byte as char).to_string()
                    } else {
                        ".".into()
                    },
                    if printable { 3 } else { 1 },
                );
            }
            append("│", 1);
            let start = text.len();
            let first_span = spans.len();
            text.push_str(&job.text);
            for section in job.sections {
                spans.push(Span {
                    text: (start + section.byte_range.start.0)..(start + section.byte_range.end.0),
                    color: section.format.color,
                });
            }
            lines.push(CodeLine {
                text: start..text.len(),
                spans: first_span..spans.len(),
            });
            text.push('\n');
        }
        Self::new(text, lines, spans, palette.size)
    }

    pub fn line_count(&self) -> usize {
        self.lines.len()
    }

    fn job(&self, line: usize) -> LayoutJob {
        let line = &self.lines[line];
        let mut job = LayoutJob {
            text: self.text[line.text.clone()].to_owned(),
            ..Default::default()
        };
        for span in &self.spans[line.spans.clone()] {
            job.sections.push(egui::text::LayoutSection {
                leading_space: 0.,
                byte_range: egui::text::ByteIndex(span.text.start - line.text.start)
                    ..egui::text::ByteIndex(span.text.end - line.text.start),
                format: TextFormat {
                    font_id: FontId::monospace(self.size),
                    color: span.color,
                    ..Default::default()
                },
            });
        }
        job
    }

    pub fn show(&self, ui: &mut egui::Ui, id: impl egui::AsIdSalt) {
        if self.wrapped {
            ui.weak("Long lines wrap in the preview; copies preserve the original text.");
        }
        let width = ui.fonts_mut(|fonts| fonts.glyph_width(&FontId::monospace(self.size), 'M'));
        egui::ScrollArea::both()
            .id_salt(id)
            .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysVisible)
            .auto_shrink([false, false])
            .show_rows(ui, self.size + 3., self.lines.len(), |ui, rows| {
                ui.set_min_width((self.columns as f32 * width).max(ui.available_width()));
                for row in rows {
                    ui.add(egui::Label::new(self.job(row)).wrap_mode(egui::TextWrapMode::Extend));
                }
            });
    }
}

#[derive(Default)]
pub(super) struct Formatted {
    pub code: Option<Code>,
    pub note: Option<String>,
}

pub(super) fn prepare(text: &str, language: Language, whole: bool, palette: Palette) -> Formatted {
    let result = if !whole {
        Err(
            "Incomplete body: showing source pages. Formatting starts when capture completes."
                .into(),
        )
    } else if text.len() > FORMAT_INPUT_LIMIT {
        Err("Body exceeds the 2 MiB formatting limit; showing source pages. Copy body / Export body preserve all captured bytes.".into())
    } else {
        format_source(text, language).and_then(|formatted| {
            if formatted.len() > FORMAT_OUTPUT_LIMIT {
                Err("Formatted output exceeds the 8 MiB limit; showing source pages. Copy body / Export body preserve all captured bytes.".into())
            } else { Ok(formatted) }
        })
    };
    match result {
        Ok(text) => Formatted {
            code: Some(Code::highlight(text, language, palette)),
            note: None,
        },
        Err(note) => Formatted {
            code: None,
            note: Some(note),
        },
    }
}

fn format_js(text: &str, extension: &str) -> Result<String, String> {
    let config = dprint_plugin_typescript::configuration::ConfigurationBuilder::new()
        .line_width(100)
        .indent_width(2)
        .build();
    dprint_plugin_typescript::format_text(dprint_plugin_typescript::FormatTextOptions {
        path: Path::new("body.js"),
        extension: Some(extension),
        text: text.to_owned(),
        config: &config,
        external_formatter: None,
    })
    .map(|formatted| formatted.unwrap_or_else(|| text.to_owned()))
    .map_err(|_| {
        "JavaScript formatter could not parse this body; displaying original source.".into()
    })
}

fn format_source(text: &str, language: Language) -> Result<String, String> {
    match language {
        Language::JavaScript | Language::TypeScript => format_js(
            text,
            if language == Language::TypeScript {
                "ts"
            } else {
                "js"
            },
        ),
        Language::Html | Language::Xml => {
            let mut options = markup_fmt::config::FormatOptions::default();
            options.layout.print_width = 100;
            options.language.script_formatter = Some(markup_fmt::config::ScriptFormatter::Dprint);
            markup_fmt::format_text(
                text,
                if language == Language::Html {
                    markup_fmt::Language::Html
                } else {
                    markup_fmt::Language::Xml
                },
                &options,
                |code, hints| {
                    if matches!(hints.ext, "js" | "ts" | "jsx" | "tsx") && !hints.attr {
                        // Embedded scripts have their own grammar; never split on braces or semicolons.
                        format_js(code, hints.ext)
                            .map(Cow::Owned)
                            .map_err(std::io::Error::other)
                            .map_err(Into::into)
                    } else {
                        Ok(Cow::Borrowed(code))
                    }
                },
            )
            .map_err(|_| {
                "Markup formatter could not parse this body; displaying original source.".into()
            })
        }
        Language::Json => serde_json::from_str::<serde_json::Value>(text)
            .and_then(|v| serde_json::to_string_pretty(&v))
            .map_err(|_| "Invalid JSON; displaying original source.".into()),
        Language::Css | Language::Text => Ok(text.to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn palette() -> Palette {
        Palette {
            colors: [
                Color32::WHITE,
                Color32::GRAY,
                Color32::RED,
                Color32::GREEN,
                Color32::BLUE,
                Color32::YELLOW,
                Color32::LIGHT_BLUE,
                Color32::GOLD,
                Color32::LIGHT_RED,
            ],
            size: 13.,
        }
    }

    #[test]
    fn javascript_formatter_preserves_literals_regex_comments_and_asi() {
        let source = "function f(){return\n{ok:true}}const url='https://a.test/a;b';const re=/[{};]+/g;const t=`a;${1+2}<b>`;/* keep ; {} */";
        let pretty = format_source(source, Language::JavaScript).unwrap();
        assert!(pretty.lines().count() > 5);
        for literal in [
            "https://a.test/a;b",
            "/[{};]+/g",
            "`a;${1 + 2}<b>`",
            "/* keep ; {} */",
        ] {
            assert!(pretty.contains(literal), "{literal}: {pretty}");
        }
        assert!(
            pretty.contains("return;"),
            "automatic semicolon insertion must survive: {pretty}"
        );
        assert_eq!(
            format_source(&pretty, Language::JavaScript).unwrap(),
            pretty
        );
        assert!(format_source("const = {", Language::JavaScript).is_err());
    }

    #[test]
    fn markup_preserves_preformatted_text_attributes_and_embedded_scripts() {
        let source = "<!doctype html><html><body><pre> a\n  b &amp; c</pre><div data-x=\"a>b;{c}\">Hello <b>world</b>!</div><script>const x={a:1};const re=/[<>;]/g;</script></body></html>";
        let pretty = format_source(source, Language::Html).unwrap();
        for literal in [
            "<pre> a\n  b &amp; c</pre>",
            "data-x=\"a>b;{c}\"",
            "Hello <b>world</b>!",
            "/[<>;]/g",
        ] {
            assert!(pretty.contains(literal), "{literal}: {pretty}");
        }
        assert!(pretty.contains("const x = { a: 1 };"));
        assert_eq!(format_source(&pretty, Language::Html).unwrap(), pretty);
    }

    #[test]
    fn bounded_formatter_never_formats_partial_pages_or_discards_source() {
        assert!(
            prepare("const x = 1;", Language::JavaScript, false, palette())
                .code
                .is_none()
        );
        let source = " ".repeat(FORMAT_INPUT_LIMIT + 1);
        assert!(
            prepare(&source, Language::Html, true, palette())
                .code
                .is_none()
        );
        let invalid = "<div title=\"unfinished";
        assert!(
            prepare(invalid, Language::Html, true, palette())
                .note
                .is_some()
        );
        let code = Code::highlight(invalid.into(), Language::Html, palette());
        assert_eq!(code.text, invalid);
        let compact = format!(
            "{}{}0{}",
            "[".repeat(100),
            "0,".repeat(60_000),
            "]".repeat(100)
        );
        assert!(compact.len() < FORMAT_INPUT_LIMIT);
        let expanded = prepare(&compact, Language::Json, true, palette());
        assert!(expanded.code.is_none());
        assert!(expanded.note.unwrap().contains("8 MiB"));
    }

    #[test]
    fn grammars_produce_distinct_spans_and_keep_multiline_comment_state() {
        for (language, source) in [
            (
                Language::JavaScript,
                "/* comment\nstill comment */ const n = 42; const s = \"hello\";",
            ),
            (Language::Html, "<div class=\"a\">text</div>"),
            (Language::Css, "body { color: #abcdef; display: none; }"),
            (Language::Json, "{\"ok\": true, \"n\": 42}"),
        ] {
            let code = Code::highlight(source.into(), language, palette());
            let colors: std::collections::HashSet<_> = code.spans.iter().map(|s| s.color).collect();
            assert!(colors.len() >= 3, "{language:?}: {colors:?}");
            if language == Language::JavaScript {
                assert_eq!(code.job(1).sections[0].format.color, palette().colors[1]);
            }
        }
    }

    #[test]
    fn hex_uses_absolute_offsets_ascii_and_semantic_colors() {
        let code = Code::hex(&[0, 10, b'A', 255], 65536, palette());
        assert!(code.text.starts_with("00010000  00 0a 41 ff"));
        assert!(code.text.contains("│..A.│"));
        assert!(
            code.job(0)
                .sections
                .iter()
                .any(|s| s.format.color == palette().colors[7])
        );
    }

    #[test]
    fn very_long_utf8_lines_have_bounded_layout_without_changing_copies() {
        let source = format!("{} final-marker", "🦀".repeat(20_000));
        let code = Code::highlight(source.clone(), Language::Text, palette());
        assert_eq!(code.text, source);
        assert!(code.wrapped);
        let mut joined = String::new();
        for (row, line) in code.lines.iter().enumerate() {
            assert!(line.text.len() <= DISPLAY_LINE_BYTES);
            let job = code.job(row);
            joined.push_str(&job.text);
            for section in job.sections {
                assert!(job.text.is_char_boundary(section.byte_range.start.0));
                assert!(job.text.is_char_boundary(section.byte_range.end.0));
            }
        }
        assert_eq!(joined, source);
    }

    #[test]
    fn mime_detection_respects_headers_and_ignores_url_query() {
        assert_eq!(
            Language::detect("Application/Problem+JSON; charset=utf-8", "/a.js"),
            Language::Json
        );
        assert_eq!(Language::detect("text/html", "/a.js"), Language::Html);
        assert_eq!(
            Language::detect("text/plain", "/a.mjs?v=.html"),
            Language::JavaScript
        );
        assert_eq!(Language::detect("image/png", "/a.js"), Language::Text);
    }
}
