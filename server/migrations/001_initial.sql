-- Create SBOMs table
CREATE TABLE IF NOT EXISTS sboms (
    id UUID PRIMARY KEY,
    project VARCHAR(255) NOT NULL,
    version VARCHAR(100) NOT NULL,
    format VARCHAR(50) NOT NULL,
    data JSONB NOT NULL,
    hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    created_by VARCHAR(255) NOT NULL
);

-- Create Attestations table  
CREATE TABLE IF NOT EXISTS attestations (
    id UUID PRIMARY KEY,
    subject_id UUID NOT NULL,
    attestation_type VARCHAR(100) NOT NULL,
    signature TEXT NOT NULL,
    certificate TEXT NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    verifier VARCHAR(255) NOT NULL,
    FOREIGN KEY (subject_id) REFERENCES sboms(id) ON DELETE CASCADE
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_sboms_project ON sboms(project);
CREATE INDEX IF NOT EXISTS idx_sboms_created_at ON sboms(created_at);
CREATE INDEX IF NOT EXISTS idx_attestations_subject_id ON attestations(subject_id);
CREATE INDEX IF NOT EXISTS idx_attestations_timestamp ON attestations(timestamp);