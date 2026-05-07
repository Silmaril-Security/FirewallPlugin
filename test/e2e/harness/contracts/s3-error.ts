export type S3ErrorCode =
  | "ExpiredToken"
  | "OperationAborted"
  | "SlowDown"
  | "RequestTimeout"
  | "EntityTooLarge"
  | "InvalidAccessKeyId"
  | "SignatureDoesNotMatch";

export type S3XmlError = {
  Error: {
    Code: S3ErrorCode;
    Message?: string;
  };
};
