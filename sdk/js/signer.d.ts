// Type definitions for the Signer browser SDK 1.0
export interface CertificateInfo {
  id: string;
  commonName: string;
  subject: string;
  organization?: string;
  organizationalUnit?: string;
  title?: string;
  email?: string;
  serialNumber: string;
  issuer: string;
  issuerCommonName?: string;
  notBefore: string;
  notAfter: string;
  currentlyValid: boolean;
  keyUsage: string[];
  keyAlgorithm: string;
  keySize: number;
  certificateClass?: string;
  policies: string[];
  source: string;
  /** Base64 DER */
  certificate: string;
}

export interface CertificateFilter {
  id?: string;
  commonName?: string;
  serialNumber?: string;
  issuer?: string;
  organization?: string;
  organizationalUnit?: string;
  title?: string;
  email?: string;
  certificateClass?: string;
}

export interface PdfSignOptions {
  visible?: boolean;
  page?: string | number;
  x?: number;
  y?: number;
  width?: number;
  height?: number;
  origin?: 'bottom-left' | 'top-left';
  reason?: string;
  location?: string;
  contactInfo?: string;
  signerName?: string;
  dateFormat?: string;
  timeZone?: string;
  greenTick?: boolean;
  border?: boolean;
  customText?: string;
  showReason?: boolean;
  showLocation?: boolean;
  fontSize?: number;
  imageBase64?: string;
  fieldName?: string;
  subFilter?: 'adbe.pkcs7.detached' | 'ETSI.CAdES.detached';
  certificationLevel?: 1 | 2 | 3;
  timestamp?: boolean;
  ltv?: boolean;
  pdfPassword?: string;
}

export type PdfInput = Blob | ArrayBuffer | Uint8Array | string;

export interface SignedPdf {
  base64: string;
  bytes: Uint8Array;
  blob: Blob;
  certificate: CertificateInfo;
  txn: string;
  chain?: string[];
  timestamped?: boolean;
}

export class SignerError extends Error {
  code: string;
  status: number;
}

export interface SignerClientOptions {
  agentUrl?: string;
  serverUrl?: string;
  getToken?: () => Promise<string | { token: string }>;
  timeoutMs?: number;
  reportCompletion?: boolean;
}

export class SignerClient {
  constructor(opts?: SignerClientOptions);
  status(): Promise<any>;
  isAvailable(): Promise<boolean>;
  certificates(args?: { token?: string; filter?: CertificateFilter }): Promise<CertificateInfo[]>;
  signPdf(args: { pdf: PdfInput; name?: string; options?: PdfSignOptions; certificate?: CertificateFilter; token?: string }): Promise<SignedPdf>;
  signPdfs(args: { documents: { pdf: PdfInput; name?: string; options?: PdfSignOptions }[]; options?: PdfSignOptions;
                   certificate?: CertificateFilter; token?: string }): Promise<{ txn: string; certificate: CertificateInfo; documents: (SignedPdf & { name: string })[] }>;
  signHash(args: { digest: string | { id: string; digest: string }[]; format?: 'cms' | 'pades' | 'raw'; timestamp?: boolean;
                   certificate?: CertificateFilter; documentNames?: string[]; token?: string; serverCompletes?: boolean }): Promise<any>;
  signPdfOnServer(args: { pdf: PdfInput; name?: string; options?: PdfSignOptions; certificate?: CertificateFilter; token?: string;
                          chooseCertificate?: (list: CertificateInfo[]) => Promise<CertificateInfo> }): Promise<SignedPdf>;
  verify(args: { pdf: PdfInput; password?: string; token?: string }): Promise<any>;
}

export function toBase64(input: PdfInput): Promise<string>;
export function base64ToBytes(b64: string): Uint8Array;
export function download(blob: Blob, fileName?: string): void;
export const version: string;
