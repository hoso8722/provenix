//! Pipeline orchestration module
//! 
//! This module handles the execution pipeline for SBOM generation,
//! attestation, signing, and verification workflows.

use anyhow::Result;

/// Pipeline execution context
#[derive(Debug, Clone)]
pub struct PipelineContext {
    pub workdir: std::path::PathBuf,
    pub verbose: bool,
}

impl Default for PipelineContext {
    fn default() -> Self {
        Self {
            workdir: std::env::current_dir().unwrap_or_default(),
            verbose: false,
        }
    }
}

/// Pipeline builder for composing workflow steps
pub struct PipelineBuilder {
    context: PipelineContext,
    steps: Vec<Box<dyn PipelineStep>>,
}

/// Trait for pipeline steps
pub trait PipelineStep: Send + Sync {
    fn execute(&self, context: &PipelineContext) -> Result<()>;
    fn name(&self) -> &str;
}

impl PipelineBuilder {
    pub fn new(context: PipelineContext) -> Self {
        Self {
            context,
            steps: Vec::new(),
        }
    }
    
    pub fn add_step<S: PipelineStep + 'static>(mut self, step: S) -> Self {
        self.steps.push(Box::new(step));
        self
    }
    
    pub fn execute(self) -> Result<()> {
        for step in &self.steps {
            log::info!("Executing step: {}", step.name());
            step.execute(&self.context)?;
        }
        Ok(())
    }
}
