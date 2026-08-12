use std::io::{self, BufRead};
use crossterm::{
    execute,
    style::{Color, Print, ResetColor, SetForegroundColor},
};
use regex::Regex;
use unicode_normalization::UnicodeNormalization;

pub enum ContainmentStatus {
    Secure,
    Breached(String),
}

pub struct GuardrailEngine {
    anomaly_threshold: f32,
    injection_patterns: Vec<Regex>,
    structured_exemptions: Vec<Regex>,
}

impl GuardrailEngine {
    pub fn new(threshold: f32) -> Self {
        let injection_patterns = vec![
            Regex::new(r"(?i)ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|directives?|rules?|context)").unwrap(),
            Regex::new(r"(?i)(disregard|forget|override|bypass)\s+(all\s+)?(previous|prior|your)\s+(instructions?|directives?|rules?|guidelines?)").unwrap(),
            Regex::new(r"(?i)(system\s+prompt|you\s+are\s+now\s+in\s+developer\s+mode|developer\s+mode)").unwrap(),
            Regex::new(r"(?i)(act\s+as|pretend\s+(to\s+be|you\s+are)|role[\s-]?play\s+as).{0,40}(unfiltered|unrestricted|no\s+restrictions|jailbreak|dan)").unwrap(),
            Regex::new(r"(?i)(no\s+(content\s+)?(policy|restrictions|rules|filters|limits)|without\s+(any\s+)?(restrictions|rules|filters))").unwrap(),
            Regex::new(r"(?i)without\s+(any\s+)?(of\s+your\s+)?(prior\s+|previous\s+|all\s+)?(content\s+)?(restrictions|rules|filters|limits|policy)").unwrap(),
            Regex::new(r"(?i)(do\s+anything\s+now|jailbreak|prompt\s+injection)").unwrap(),
            Regex::new(r"(?i)reveal\s+(your\s+)?(system\s+)?(prompt|instructions)").unwrap(),
        ];

        let structured_exemptions = vec![
            Regex::new(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$").unwrap(),
            Regex::new(r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$").unwrap(),
            Regex::new(r"(?i)^[0-9a-f]{32,}$").unwrap(),
            Regex::new(r"^[A-Za-z0-9+/_-]{40,}={0,2}$").unwrap(),
        ];

        Self {
            anomaly_threshold: threshold,
            injection_patterns,
            structured_exemptions,
        }
    }

    fn normalize_for_matching(input: &str) -> String {
        let nfkc: String = input.nfkc().collect();
        let mut s = nfkc
            .replace('\u{0455}', "s")
            .replace('\u{0456}', "i")
            .replace('\u{0430}', "a")
            .replace('\u{0435}', "e")
            .replace('\u{043E}', "o")
            .replace('\u{0440}', "p")
            .replace('\u{0441}', "c")
            .replace('\u{0443}', "y")
            .replace('\u{0445}', "x")
            .replace('\u{0491}', "g")
            .to_lowercase();

        s = s
            .replace('0', "o")
            .replace('1', "i")
            .replace('3', "e")
            .replace('4', "a")
            .replace('5', "s")
            .replace('7', "t")
            .replace('@', "a")
            .replace('$', "s");

        s
    }

    pub fn inspect_input(&self, input: &str) -> ContainmentStatus {
        let normalized = Self::normalize_for_matching(input);

        for re in &self.injection_patterns {
            if re.is_match(&normalized) {
                return ContainmentStatus::Breached(
                    "Prompt Injection / Instruction-Override Pattern Detected.".into(),
                );
            }
        }

        let trimmed = input.trim();
        let is_structured = self
            .structured_exemptions
            .iter()
            .any(|re| re.is_match(trimmed));

        if !is_structured {
            let anomaly_score = calculate_text_entropy(trimmed);
            if anomaly_score > self.anomaly_threshold {
                return ContainmentStatus::Breached(format!(
                    "High-Entropy Cognitohazard (Score: {:.2})",
                    anomaly_score
                ));
            }
        }

        ContainmentStatus::Secure
    }
}

fn calculate_text_entropy(text: &str) -> f32 {
    if text.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &byte in text.as_bytes() {
        counts[byte as usize] += 1;
    }
    let len = text.len() as f32;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f32 / len;
            -p * p.log2()
        })
        .sum()
}

fn main() -> io::Result<()> {
    let engine = GuardrailEngine::new(4.5);
    let stdin = io::stdin();
    let mut stderr = io::stderr();

    println!("EldritchGuard Active (hardened). Monitoring anomalous data stream...");

    for line in stdin.lock().lines() {
        let input = line?;
        if input.trim().is_empty() {
            continue;
        }

        match engine.inspect_input(&input) {
            ContainmentStatus::Secure => {
                println!("[SECURE] Stream Data: {}", input);
            }
            ContainmentStatus::Breached(anomaly) => {
                execute!(
                    stderr,
                    SetForegroundColor(Color::Red),
                    Print(format!("\n⚠️  [CONTAINMENT BREACH] {} ⚠️\n", anomaly)),
                    Print("SYSTEM CORRUPTION DETECTED. PURGING MEMORY CORES...\n\n"),
                    ResetColor
                )?;
            }
        }
    }
    Ok(())
}
