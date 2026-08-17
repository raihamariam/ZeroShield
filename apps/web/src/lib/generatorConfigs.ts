/**
 * Structured field specs for each dataset generator's config class. There is no API
 * endpoint that exposes a generator's config schema (GenerateDatasetRequest.config /
 * CreateExperimentVersionRequest.dataset_config are both just Record<string, unknown>,
 * validated server-side against the matching Pydantic model) - these mirror the real
 * field constraints in src/zeroshield/generators/{vpn,telecom}_generator.py exactly, so
 * Experiment Studio can render typed number inputs instead of a bare JSON blob. If a
 * generator's Python config class changes, this must be updated to match, and any
 * generator not listed here falls back to the raw-JSON editor automatically.
 */

export interface GeneratorFieldSpec {
  key: string;
  label: string;
  min?: number;
  max?: number;
  default: number;
  hint?: string;
}

export const GENERATOR_CONFIGS: Record<string, GeneratorFieldSpec[]> = {
  vpn_pre_auth_request_generator: [
    { key: "valid_count", label: "Valid cases", min: 0, max: 50, default: 4 },
    { key: "boundary_count", label: "Boundary cases", min: 0, max: 10, default: 1, hint: "path length at/over the max" },
    { key: "oversized_count", label: "Oversized body cases", min: 0, max: 20, default: 2 },
    { key: "duplicate_field_count", label: "Duplicate header cases", min: 0, max: 20, default: 2 },
    { key: "mismatched_length_count", label: "Mismatched length cases", min: 0, max: 20, default: 2 },
    { key: "unsupported_encoding_count", label: "Unsupported encoding cases", min: 0, max: 20, default: 2 },
    { key: "invalid_path_count", label: "Invalid path cases", min: 0, max: 20, default: 2 },
    { key: "max_path_length", label: "Max path length", min: 1, default: 256 },
    { key: "max_body_length", label: "Max body length", min: 1, default: 8192 },
    { key: "max_header_value_length", label: "Max header value length", min: 1, default: 512 },
  ],
  telecom_sip_session_setup_generator: [
    { key: "valid_count", label: "Valid cases", min: 0, max: 50, default: 4 },
    { key: "boundary_count", label: "Boundary cases", min: 0, max: 10, default: 1, hint: "SDP attribute length at/over the max" },
    { key: "oversized_field_count", label: "Oversized field cases", min: 0, max: 20, default: 2 },
    { key: "missing_header_count", label: "Missing header cases", min: 0, max: 20, default: 2 },
    { key: "duplicate_identity_count", label: "Duplicate identity cases", min: 0, max: 20, default: 2 },
    { key: "mismatched_length_count", label: "Mismatched length cases", min: 0, max: 20, default: 2 },
    { key: "invalid_sequence_count", label: "Invalid sequence cases", min: 0, max: 20, default: 2 },
    { key: "invalid_transition_count", label: "Invalid transition cases", min: 0, max: 20, default: 2 },
    { key: "max_sdp_attr_value_length", label: "Max SDP attribute value length", min: 1, default: 256 },
    { key: "max_body_length", label: "Max body length", min: 1, default: 4096 },
  ],
};

export function defaultConfigFor(generatorId: string): Record<string, number> {
  const spec = GENERATOR_CONFIGS[generatorId];
  if (!spec) return {};
  return Object.fromEntries(spec.map((f) => [f.key, f.default]));
}
