export interface StorageDevice {
  id: string;
  path: string;
  model: string;
  interface: 'NVMe PCIe 4.0' | 'SATA SSD' | 'HDD' | 'USB 3.2 Flash' | 'Forensic Image (E01/DD)';
  capacityBytes: number;
  sectorSize: number;
  writeBlockerActive: boolean;
  filesystem: string;
  serialNumber: string;
  smartStatus: 'HEALTHY' | 'WARNING' | 'CRITICAL';
  healthPercent: number;
  partitionTable: 'GPT' | 'MBR';
  sectorCount: number;
}

export interface RecoveredArtifact {
  id: string;
  filename: string;
  fileType: string;
  sizeBytes: number;
  sectorOffset: number;
  inodeCluster: string;
  sha256: string;
  recoveryIntegrity: '100% Intact' | 'High' | 'Partial Carved';
  timestamps: {
    modified: string;
    accessed: string;
    created: string;
    born: string;
  };
  metadata: {
    cameraMake?: string;
    lens?: string;
    gps?: string;
    resolution?: string;
    author?: string;
    pages?: number;
    pdfVersion?: string;
    ntfsAttributes?: string;
    packetCount?: number;
    protocols?: string;
    sqlitePageSize?: number;
    tables?: string;
    carverHeader?: string;
    carverFooter?: string;
  };
  hexPreview: string;
  asciiPreview: string;
  carvedBy: 'sleuthkit_tsk_recover' | 'sleuthkit_fls' | 'foremost_carver';
}

export interface SanitizationResult {
  operationId: string;
  targetDevice: string;
  standardApplied: string;
  passesCompleted: number;
  totalBytesWiped: number;
  preWipeSha256: string;
  postWipeSha256: string;
  verificationStatus: string;
  metadataWiped: boolean;
  unallocatedWiped: boolean;
  executionTimeSeconds: number;
  timestamp: string;
  entropy: number;
}

export interface AuditLogEntry {
  id: string;
  operationId: string;
  timestamp: string;
  domain: 'RECOVERY' | 'SANITIZATION';
  deviceModel: string;
  devicePath: string;
  pipelineOrStandard: string;
  preSha256: string;
  postSha256: string;
  status: string;
  caseRef: string;
  operator: string;
  artifactsCount?: number;
}

export interface AIActionPlan {
  action: 'EXECUTE_RECOVERY' | 'EXECUTE_SANITIZATION';
  domain: 'RECOVERY' | 'SANITIZATION';
  plan_title: string;
  steps: string[];
  parameters: {
    standard?: string;
    enable_sleuthkit?: boolean;
    enable_carving?: boolean;
    wipe_metadata?: boolean;
    wipe_unallocated?: boolean;
    write_blocker_required?: boolean;
  };
  safety_confirmation_required: boolean;
}

export interface ChatMessage {
  id: string;
  sender: 'user' | 'assistant' | 'system';
  text: string;
  timestamp: string;
  actionPlan?: AIActionPlan;
  isThinking?: boolean;
  webSources?: Array<{ title: string; url: string }>;
  searchQueries?: string[];
}

export interface PythonSourceFile {
  filename: string;
  content: string;
  sizeBytes: number;
}
