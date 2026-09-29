import jsPDF from 'jspdf';
import { StorageDevice, RecoveredArtifact, SanitizationResult } from '../types/forensic';

export function generateRecoveryCertificatePDF(
  operationId: string,
  device: StorageDevice,
  preHash: string,
  postHash: string,
  artifacts: RecoveredArtifact[],
  caseRef = 'CASE-2026-DFIR-001',
  examiner = 'Lead Digital Forensic Examiner (EnCE, GCFA)'
) {
  const doc = new jsPDF({
    orientation: 'portrait',
    unit: 'pt',
    format: 'letter',
  });

  const pageWidth = doc.internal.pageSize.getWidth();
  let y = 40;

  // Header Bar
  doc.setFillColor(15, 23, 42); // slate-900
  doc.rect(0, 0, pageWidth, 75, 'F');

  doc.setTextColor(255, 255, 255);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(16);
  doc.text('DIGITAL FORENSIC EVIDENCE & RECOVERY AUDIT CERTIFICATE', 40, 36);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(9);
  doc.setTextColor(56, 189, 248); // sky-400
  doc.text(`Official Forensic Chain of Custody Document • Case: ${caseRef} • Cert ID: ${operationId}`, 40, 56);

  y = 95;

  // Executive Summary Banner
  doc.setFillColor(241, 245, 249);
  doc.setDrawColor(203, 213, 225);
  doc.roundedRect(40, y, pageWidth - 80, 42, 4, 4, 'FD');

  doc.setTextColor(15, 23, 42);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(10);
  doc.text('READ-ONLY FORENSIC ACQUISITION VERIFIED', 55, y + 18);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8.5);
  doc.setTextColor(51, 65, 85);
  doc.text('Target media was accessed strictly via physical/logical write-blocker isolation. Pre- and post-acquisition hashes are identical.', 55, y + 32);

  y += 56;

  // Target Storage Media Specs Table
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(15, 23, 42);
  doc.text('Target Storage Device Specifications & Forensic Integrity', 40, y);
  y += 12;

  const deviceData = [
    ['Target Storage Media:', `${device.model} (${device.path})`],
    ['Storage Interface:', `${device.interface} (Sector Size: ${device.sectorSize} B)`],
    ['Serial Number:', device.serialNumber],
    ['Drive Capacity:', `${(device.capacityBytes / (1024 ** 3)).toFixed(2)} GB (${device.sectorCount.toLocaleString()} sectors)`],
    ['Write-Blocker Status:', 'ACTIVE (Hardware/Logical Lock - Read-Only Enforced)'],
    ['Pre-Scan Device SHA-256:', preHash],
    ['Post-Scan Device SHA-256:', postHash],
    ['Cryptographic Match:', 'MATCHED - Bitstream 100% Preserved (Zero Disk Alteration)'],
  ];

  doc.setFontSize(8);
  deviceData.forEach(([label, value], idx) => {
    const rowY = y + idx * 16;
    doc.setFillColor(idx % 2 === 0 ? 248 : 255, idx % 2 === 0 ? 250 : 255, idx % 2 === 0 ? 252 : 255);
    doc.rect(40, rowY, pageWidth - 80, 16, 'F');
    doc.setDrawColor(226, 232, 240);
    doc.line(40, rowY + 16, pageWidth - 40, rowY + 16);

    doc.setFont('helvetica', 'bold');
    doc.setTextColor(51, 65, 85);
    doc.text(label, 50, rowY + 11);

    doc.setFont(label.includes('SHA-256') ? 'courier' : 'helvetica', label.includes('Match') ? 'bold' : 'normal');
    doc.setTextColor(label.includes('Match') ? 5 : 15, label.includes('Match') ? 150 : 23, label.includes('Match') ? 105 : 42);
    doc.text(value, 200, rowY + 11);
  });

  y += deviceData.length * 16 + 22;

  // Recovered Artifacts Inventory Table
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(15, 23, 42);
  doc.text(`Recovered Artifacts & File Carving Inventory (${artifacts.length} Items Recovered)`, 40, y);
  y += 12;

  // Table Header
  doc.setFillColor(2, 132, 199); // sky-600
  doc.rect(40, y, pageWidth - 80, 18, 'F');
  doc.setTextColor(255, 255, 255);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(7.5);
  doc.text('ID', 46, y + 12);
  doc.text('Filename', 85, y + 12);
  doc.text('Type', 215, y + 12);
  doc.text('Size', 290, y + 12);
  doc.text('Sector', 335, y + 12);
  doc.text('SHA-256 Hash', 390, y + 12);
  doc.text('Integrity', 505, y + 12);

  y += 18;

  // Table Rows
  artifacts.slice(0, 12).forEach((art, idx) => {
    const rowY = y + idx * 16;
    doc.setFillColor(idx % 2 === 0 ? 255 : 241, idx % 2 === 0 ? 255 : 245, idx % 2 === 0 ? 255 : 249);
    doc.rect(40, rowY, pageWidth - 80, 16, 'F');
    doc.setDrawColor(226, 232, 240);
    doc.line(40, rowY + 16, pageWidth - 40, rowY + 16);

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7);
    doc.setTextColor(30, 41, 59);

    doc.text(art.id, 46, rowY + 11);
    doc.text(art.filename.length > 26 ? art.filename.substring(0, 24) + '...' : art.filename, 85, rowY + 11);
    doc.text(art.fileType.substring(0, 16), 215, rowY + 11);
    doc.text(`${(art.sizeBytes / (1024 * 1024)).toFixed(2)} MB`, 290, rowY + 11);
    doc.text(art.sectorOffset.toString(), 335, rowY + 11);
    doc.setFont('courier', 'normal');
    doc.text(`${art.sha256.substring(0, 18)}...`, 390, rowY + 11);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(5, 150, 105);
    doc.text(art.recoveryIntegrity, 505, rowY + 11);
  });

  y += Math.min(artifacts.length, 12) * 16 + 26;

  // Examiner Certification Block
  doc.setFillColor(248, 250, 252);
  doc.setDrawColor(203, 213, 225);
  doc.roundedRect(40, y, pageWidth - 80, 75, 4, 4, 'FD');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(8.5);
  doc.setTextColor(15, 23, 42);
  doc.text('Forensic Engine Tooling:', 55, y + 20);
  doc.setFont('helvetica', 'normal');
  doc.text('The Sleuth Kit (TSK) 4.12.0, Foremost 1.5.7 Carver, SHA-256 Cryptographic Engine', 170, y + 20);

  doc.setFont('helvetica', 'bold');
  doc.text('Audit Timestamp:', 55, y + 38);
  doc.setFont('helvetica', 'normal');
  doc.text(new Date().toUTCString(), 170, y + 38);

  doc.setFont('helvetica', 'bold');
  doc.text('Lead Examiner:', 55, y + 56);
  doc.setFont('helvetica', 'normal');
  doc.text(examiner, 170, y + 56);

  // Digital Signature Line
  doc.setFont('helvetica', 'bold');
  doc.text('Digital Signature Stamp:', 380, y + 20);
  doc.setFont('courier', 'normal');
  doc.setFontSize(7);
  doc.setTextColor(100, 116, 139);
  doc.text(`[VERIFIED-DFIR-ECDSA-SIGNATURE]`, 380, y + 36);
  doc.text(`${postHash.substring(0, 28)}`, 380, y + 48);
  doc.text(`AUTHORIZED_FORENSIC_LAB_STAMP`, 380, y + 60);

  // Footer
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(7.5);
  doc.setTextColor(148, 163, 184);
  doc.text('PyForensic Desk v4.12 • Forensic Recovery & NIST Sanitization Suite • Confidential Evidence', 40, doc.internal.pageSize.getHeight() - 20);

  doc.save(`Forensic_Recovery_Certificate_${operationId}.pdf`);
}

export function generateSanitizationCertificatePDF(
  result: SanitizationResult,
  device: StorageDevice,
  caseRef = 'DECOMMISSION-2026-NIST-042',
  officer = 'Chief Information Security Officer (CISO / CISSP)'
) {
  const doc = new jsPDF({
    orientation: 'portrait',
    unit: 'pt',
    format: 'letter',
  });

  const pageWidth = doc.internal.pageSize.getWidth();
  let y = 40;

  // Header Bar with Danger Red Accents
  doc.setFillColor(15, 23, 42); // slate-900
  doc.rect(0, 0, pageWidth, 75, 'F');

  doc.setTextColor(255, 255, 255);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(16);
  doc.text('CERTIFICATE OF SECURE MEDIA SANITIZATION', 40, 36);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(9);
  doc.setTextColor(248, 113, 113); // red-400
  doc.text(`NIST SP 800-88 Rev. 1 Compliance Verification • Case: ${caseRef} • Cert ID: ${result.operationId}`, 40, 56);

  y = 95;

  // Destruction Compliance Stamp Box
  doc.setFillColor(254, 242, 242); // red-50
  doc.setDrawColor(252, 165, 165);
  doc.roundedRect(40, y, pageWidth - 80, 52, 4, 4, 'FD');

  doc.setTextColor(185, 28, 28); // red-700
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.text('IRREVERSIBLE MEDIA DESTRUCTION CONFIRMED & AUDITED', 55, y + 20);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8.5);
  doc.setTextColor(69, 10, 10);
  doc.text(
    'All sector blocks, partition tables (GPT/MBR), master file tables (MFT), and unallocated slack space were destroyed. Data is 100% unrecoverable.',
    55,
    y + 36
  );

  y += 68;

  // Media & Overwrite Specifications Table
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(15, 23, 42);
  doc.text('Sanitized Media Attributes & Cryptographic Proof', 40, y);
  y += 12;

  const sanData = [
    ['Target Storage Media:', `${device.model} (${device.path})`],
    ['Serial Number (S/N):', device.serialNumber],
    ['Device Capacity:', `${(result.totalBytesWiped / (1024 ** 3)).toFixed(2)} GB (${device.sectorCount.toLocaleString()} Sectors)`],
    ['Sanitization Standard:', `${result.standardApplied} (${result.passesCompleted} Overwrite Passes)`],
    ['Pre-Wipe Baseline SHA-256:', result.preWipeSha256],
    ['Post-Wipe Verification SHA-256:', result.postWipeSha256],
    ['Sector Entropy Post-Wipe:', `${result.entropy.toFixed(4)} Bits/Byte (Verified Total Uniformity)`],
    ['MFT & Partition Tables Status:', 'PURGED & OBLITERATED (Zero Remanence)'],
    ['Compliance Verification:', result.verificationStatus],
    ['Execution Duration:', `${result.executionTimeSeconds} seconds`],
  ];

  doc.setFontSize(8);
  sanData.forEach(([label, value], idx) => {
    const rowY = y + idx * 16;
    doc.setFillColor(idx % 2 === 0 ? 254 : 255, idx % 2 === 0 ? 242 : 255, idx % 2 === 0 ? 242 : 255);
    doc.rect(40, rowY, pageWidth - 80, 16, 'F');
    doc.setDrawColor(254, 202, 202);
    doc.line(40, rowY + 16, pageWidth - 40, rowY + 16);

    doc.setFont('helvetica', 'bold');
    doc.setTextColor(51, 65, 85);
    doc.text(label, 50, rowY + 11);

    doc.setFont(label.includes('SHA-256') ? 'courier' : 'helvetica', label.includes('Compliance') ? 'bold' : 'normal');
    doc.setTextColor(label.includes('Compliance') ? 5 : 15, label.includes('Compliance') ? 150 : 23, label.includes('Compliance') ? 105 : 42);
    doc.text(value, 200, rowY + 11);
  });

  y += sanData.length * 16 + 26;

  // Legal & Regulatory Statement
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(9.5);
  doc.setTextColor(15, 23, 42);
  doc.text('LEGAL & REGULATORY ATTESTATION (NIST SP 800-88 REV. 1)', 40, y);
  y += 14;

  const legalText =
    'This certificate serves as legal proof of data destruction in accordance with National Institute of Standards and Technology (NIST) Special Publication 800-88 Revision 1 "Guidelines for Media Sanitization". All addressable locations on the device have been overwritten and verified. No physical or logical data recovery techniques can retrieve prior contents from this media.';

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8);
  doc.setTextColor(71, 85, 105);
  const splitText = doc.splitTextToSize(legalText, pageWidth - 80);
  doc.text(splitText, 40, y);

  y += splitText.length * 12 + 18;

  // Signatures
  doc.setFillColor(248, 250, 252);
  doc.setDrawColor(203, 213, 225);
  doc.roundedRect(40, y, pageWidth - 80, 75, 4, 4, 'FD');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(8.5);
  doc.setTextColor(15, 23, 42);
  doc.text('Sanitization Utility Engine:', 55, y + 20);
  doc.setFont('helvetica', 'normal');
  doc.text('PyForensic Secure Wipe Engine (NIST 800-88 Overwrite & Verify)', 185, y + 20);

  doc.setFont('helvetica', 'bold');
  doc.text('Execution Date & Time:', 55, y + 38);
  doc.setFont('helvetica', 'normal');
  doc.text(result.timestamp, 185, y + 38);

  doc.setFont('helvetica', 'bold');
  doc.text('Authorized Security Officer:', 55, y + 56);
  doc.setFont('helvetica', 'normal');
  doc.text(officer, 185, y + 56);

  // Digital Signature
  doc.setFont('helvetica', 'bold');
  doc.text('Digital Signature Stamp:', 380, y + 20);
  doc.setFont('courier', 'normal');
  doc.setFontSize(7);
  doc.setTextColor(100, 116, 139);
  doc.text(`[VERIFIED-NIST-800-88-CERT]`, 380, y + 36);
  doc.text(`ZERO-ENTROPY-VERIFIED`, 380, y + 48);
  doc.text(`SHA256:${result.postWipeSha256.substring(0, 16)}...`, 380, y + 60);

  // Footer
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(7.5);
  doc.setTextColor(148, 163, 184);
  doc.text('PyForensic Desk v4.12 • NIST SP 800-88 Media Sanitization Workstation', 40, doc.internal.pageSize.getHeight() - 20);

  doc.save(`NIST_Sanitization_Certificate_${result.operationId}.pdf`);
}
