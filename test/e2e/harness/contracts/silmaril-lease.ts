export type SilmarilUploadLease = {
  type: "s3-post";
  bucket: "silmaril-openclaw-firewall-exports-prod";
  url: string;
  fields: Record<string, string>;
  keyPrefix: string;
  keyTemplate?: string;
  contentType?: string;
  maxObjectBytes?: number;
  expiresInSeconds?: number;
  expiresAt: string;
  fetchedAt: string;
};

export type SilmarilUploadLeaseRequest = {
  host: string;
  userEmail?: string;
};
