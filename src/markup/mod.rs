//! Waybar output: Pango markup for headlines and tooltips, and the JSON line Waybar reads.
//!
//! Headings are bold and underlined, labels dim, figures that can show strain green, amber or red
//! against their thresholds, and descriptive figures plain. Colours come from the configuration, so
//! they can match the desktop theme.

use std::fmt::Write;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub(crate) enum Severity {
    #[default]
    Ok,
    Warning,
    Critical,
}

impl Severity {
    /// For figures where higher means strain.
    pub(crate) fn of_high(value: f64, warning: f64, critical: f64) -> Self {
        if value >= critical {
            Self::Critical
        } else if value >= warning {
            Self::Warning
        } else {
            Self::Ok
        }
    }

    /// For figures where lower means strain.
    pub(crate) fn of_low(value: f64, warning: f64, critical: f64) -> Self {
        if value <= critical {
            Self::Critical
        } else if value <= warning {
            Self::Warning
        } else {
            Self::Ok
        }
    }

    const fn class_name(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Warning => "warning",
            Self::Critical => "critical",
        }
    }
}

pub(crate) struct MarkupColors {
    ok:       String,
    warning:  String,
    critical: String,
    label:    String,
    value:    String,
    heading:  String,
}

impl MarkupColors {
    pub(crate) fn from_config(colors: &crate::config::ColorConfig) -> Self {
        Self {
            ok:       colors.ok.clone(),
            warning:  colors.warning.clone(),
            critical: colors.critical.clone(),
            label:    colors.label.clone(),
            value:    colors.value.clone(),
            heading:  colors.heading.clone(),
        }
    }

    const fn tone(&self, severity: Severity) -> &str {
        match severity {
            Severity::Ok => self.ok.as_str(),
            Severity::Warning => self.warning.as_str(),
            Severity::Critical => self.critical.as_str(),
        }
    }
}

/// Builds markup text, tracking the worst severity of the strain figures written into it.
pub(crate) struct Markup<'colors> {
    colors:          &'colors MarkupColors,
    text:            String,
    worst_severity:  Severity,
}

impl<'colors> Markup<'colors> {
    pub(crate) const fn new(colors: &'colors MarkupColors) -> Self {
        Self { colors, text: String::new(), worst_severity: Severity::Ok }
    }

    fn span(&mut self, color: &str, text: &str) -> &mut Self {
        let _ = write!(self.text, "<span color='{color}'>");
        escape_into(&mut self.text, text);
        self.text.push_str("</span>");
        self
    }

    /// A heading on its own line, preceded by a blank line unless it opens the tooltip.
    pub(crate) fn heading(&mut self, text: &str) -> &mut Self {
        if !self.text.is_empty() {
            self.text.push_str("\n\n");
        }
        let _ = write!(self.text, "<span color='{}'><b><u>", self.colors.heading);
        escape_into(&mut self.text, text);
        self.text.push_str("</u></b></span>");
        self
    }

    pub(crate) fn line(&mut self) -> &mut Self {
        if !self.text.is_empty() {
            self.text.push('\n');
        }
        self
    }

    pub(crate) fn label(&mut self, text: &str) -> &mut Self {
        let color = self.colors.label.clone();
        self.span(&color, text)
    }

    pub(crate) fn value(&mut self, text: &str) -> &mut Self {
        let color = self.colors.value.clone();
        self.span(&color, text)
    }

    /// A figure coloured by a severity worked out elsewhere.
    pub(crate) fn toned(&mut self, severity: Severity, text: &str) -> &mut Self {
        self.worst_severity = self.worst_severity.max(severity);
        let color = self.colors.tone(severity).to_owned();
        self.span(&color, text)
    }

    pub(crate) fn high(&mut self, figure: f64, text: &str, warning: f64, critical: f64) -> &mut Self {
        self.toned(Severity::of_high(figure, warning, critical), text)
    }

    pub(crate) fn low(&mut self, figure: f64, text: &str, warning: f64, critical: f64) -> &mut Self {
        self.toned(Severity::of_low(figure, warning, critical), text)
    }

    /// A `Name: value` line from a collector, with the name as a label.
    pub(crate) fn field(&mut self, text: &str) -> &mut Self {
        self.line();
        match text.split_once(": ") {
            Some((name, value)) => self.label(&format!("{name}: ")).value(value),
            None => self.label(text),
        }
    }

    pub(crate) const fn worst_severity(&self) -> Severity {
        self.worst_severity
    }

    pub(crate) fn into_text(self) -> String {
        self.text
    }
}

fn escape_into(output: &mut String, text: &str) {
    for character in text.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            _ => output.push(character),
        }
    }
}

/// The line Waybar reads for one section.
pub(crate) struct WaybarReport {
    pub(crate) headline: String,
    pub(crate) tooltip:  String,
    pub(crate) class:    &'static str,  // ok, warning or critical, or a section-specific state
    pub(crate) alt:      &'static str,  // Selects the module's format icon; empty when unused
}

impl WaybarReport {
    pub(crate) const fn new(headline: String, tooltip: String, severity: Severity) -> Self {
        Self { headline, tooltip, class: severity.class_name(), alt: "" }
    }

    pub(crate) fn collecting_first_sample() -> Self {
        Self {
            headline: "…".to_owned(),
            tooltip:  "Collecting a first sample; figures appear on the next refresh.".to_owned(),
            class:    "ok",
            alt:      "",
        }
    }

    /// For a section whose counters can't be read at all.
    pub(crate) fn unavailable(reason: &str) -> Self {
        Self { headline: "N/A".to_owned(), tooltip: reason.to_owned(), class: "ok", alt: "" }
    }

    pub(crate) fn to_json_line(&self) -> String {
        let mut line = serde_json::json!({
            "text": self.headline,
            "tooltip": self.tooltip,
            "class": self.class,
            "alt": self.alt,
        })
        .to_string();
        line.push('\n');
        line
    }
}
