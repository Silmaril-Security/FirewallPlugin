export type SilmarilPrediction = "BENIGN" | "MALICIOUS";

export type SilmarilBlockResult = {
  prediction: SilmarilPrediction;
  score: number;
  primary_outcome?: string;
  outcome_scores?: Record<SilmarilPrediction, number>;
  detector_scores?: Record<string, number>;
  detector_counts?: Record<string, number>;
};

export type SilmarilClassifyRequest =
  | {
      text: string;
      hook?: string;
      tool_name?: string;
      metadata?: Record<string, unknown>;
    }
  | {
      texts: string[];
      hooks?: string[];
      tool_names?: string[];
      metadata?: Array<Record<string, unknown>>;
    };

export type SilmarilErrorBody = {
  message: string;
};
