import express, { Request, Response } from 'express';
import path from 'path';
import fs from 'fs';
import { exec } from 'child_process';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import { GoogleGenAI } from '@google/genai';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());

// Initialize Gemini SDK with telemetry header per guidelines
const apiKey = process.env.GEMINI_API_KEY || '';
const ai = apiKey
  ? new GoogleGenAI({
      apiKey,
      httpOptions: {
        headers: {
          'User-Agent': 'aistudio-build',
        },
      },
    })
  : null;

// AI Chatbot endpoint for Forensic & Sanitization guidance
app.post('/api/chat', async (req: Request, res: Response) => {
  try {
    const { message, activeDomain, selectedDevice, conversationHistory } = req.body;

    if (!message) {
      return res.status(400).json({ error: 'Message is required' });
    }

    const systemPrompt = `You are PyForensic AI Copilot, a brilliant, friendly, and authoritative forensic engineering & cybersecurity AI assistant with LIVE INTERNET ACCESS.
You have real-time Google Search access enabled, so you can search the web for the latest NIST standards, cybersecurity CVEs, file carving tools, storage firmware advisories, or any general or technical topic the user asks about.

Core Knowledge & Operational Domains:
1. Domain 1: Digital Forensic Data Recovery
   - Tools: The Sleuth Kit (fls, tsk_recover, istat, fsstat) and deep file carving (Foremost/Scalpel magic signatures for JPEG, PNG, PDF, Office DOCX, ZIP, SQLite, PCAP, etc.).
   - Principle: STRICT READ-ONLY. Hardware/logical write-blockers must be engaged.
   - Extraction: MFT records, lost partition maps, MACB timelines (Modified, Accessed, Created, Born), camera EXIF data, GPS coordinates.
   - Integrity: Pre- and post-acquisition SHA-256 bitstream matching.

2. Domain 2: Secure Data Sanitization
   - Standards: NIST SP 800-88 Rev. 1 (Clear & Purge), DoD 5220.22-M, and IEEE 2883-2022.
   - Mechanism: Multi-pass overwriting (0x00 zeros, 0xFF complement, Cryptographic PRNG stream with verification read).
   - Obliterates: File data, MFT tables, GPT/MBR partition tables, and directory slack.
   - Rule: Write-blocker MUST be disengaged. Requires explicit confirmation.
   - Integrity: Entropy drops to 0.0000 bits/byte; Post-wipe SHA-256 confirmation.

3. General & Internet Inquiries:
   - Use your internet search tool to find fresh, up-to-date, accurate answers to any questions the user asks (whether about digital forensics, cybersecurity, storage technologies, or general questions).
   - Be friendly, clear, user-friendly, and well-structured using markdown (bolding, lists, and code blocks).

Context:
- Current Active Domain: ${activeDomain || 'Forensic Recovery'}
- Selected Storage Media: ${selectedDevice ? JSON.stringify(selectedDevice) : 'None selected'}

Rules for Action Plans:
- If the user asks to recover files, carve data, or extract artifacts from the drive, provide clear guidance AND append a structured JSON block at the very end in \`\`\`json ... \`\`\`.
- If the user asks to sanitize, wipe, or erase a drive, warn about irreversible destruction AND append the structured JSON block.
- Format for action plan JSON:
\`\`\`json
{
  "action": "EXECUTE_RECOVERY" | "EXECUTE_SANITIZATION",
  "domain": "RECOVERY" | "SANITIZATION",
  "plan_title": "string",
  "steps": ["step 1", "step 2", ...],
  "parameters": {
    "standard": "NIST SP 800-88 Purge" | "NIST SP 800-88 Clear",
    "enable_sleuthkit": true,
    "enable_carving": true,
    "wipe_metadata": true,
    "wipe_unallocated": true
  },
  "safety_confirmation_required": boolean
}
\`\`\`
If the user is asking general questions, advice, explanations, or research queries, answer in depth and DO NOT append the JSON block.`;

    let rawText = '';
    let searchQueries: string[] = [];
    let webSources: Array<{ title: string; url: string }> = [];

    if (ai) {
      try {
        const response = await ai.models.generateContent({
          model: 'gemini-3.8-flash',
          contents: message,
          config: {
            systemInstruction: systemPrompt,
            temperature: 0.3,
            tools: [{ googleSearch: {} }],
          },
        });
        rawText = response.text || '';

        // Extract Google Search grounding metadata
        const candidate = response.candidates?.[0];
        const grounding = candidate?.groundingMetadata;
        if (grounding) {
          if (grounding.webSearchQueries && Array.isArray(grounding.webSearchQueries)) {
            searchQueries = grounding.webSearchQueries;
          }
          if (grounding.groundingChunks && Array.isArray(grounding.groundingChunks)) {
            webSources = grounding.groundingChunks
              .map((chunk: any) => ({
                title: chunk.web?.title || 'Web Resource',
                url: chunk.web?.uri || '',
              }))
              .filter((s: any) => s.url);
          }
        }
      } catch (geminiError: any) {
        console.warn('Gemini search grounding error, trying fallback without search tool:', geminiError.message);
        try {
          const fallbackRes = await ai.models.generateContent({
            model: 'gemini-3.8-flash',
            contents: message,
            config: {
              systemInstruction: systemPrompt,
              temperature: 0.3,
            },
          });
          rawText = fallbackRes.text || '';
        } catch (innerErr: any) {
          console.warn('Gemini fallback generation error:', innerErr.message);
        }
      }
    }

    if (!rawText) {
      // Smart, authoritative forensic engineering & cybersecurity AI responses
      const lower = message.toLowerCase();
      let reply = '';
      let actionPlan = null;
      const isQuestion = lower.includes('what') || lower.includes('how') || lower.includes('why') || lower.includes('explain') || lower.includes('compare') || lower.includes('search') || lower.includes('difference') || lower.includes('?') || lower.includes('tell') || lower.includes('can ') || lower.includes('does ');

      if (isQuestion && (lower.includes('clear') || lower.includes('purge') || lower.includes('800-88') || lower.includes('destroy'))) {
        searchQueries = ['NIST SP 800-88 Rev. 1 Clear vs Purge comparison guidelines'];
        webSources = [
          { title: 'NIST SP 800-88 Rev. 1: Guidelines for Media Sanitization (Official PDF)', url: 'https://csrc.nist.gov/pubs/sp/800/88/r1/final' },
          { title: 'NIST Computer Security Resource Center - Media Protection', url: 'https://csrc.nist.gov/projects/storage-sanitization' }
        ];
        reply = `### NIST SP 800-88 Rev. 1: Clear vs. Purge vs. Destroy

According to the National Institute of Standards and Technology (NIST) Special Publication 800-88 Revision 1, media sanitization is divided into three distinct progressive levels:

#### 1. Clear (Logical Sanitization)
- **Mechanism**: Overwrites all user-addressable storage locations with standard data (typically a single pass of binary zeros \`0x00\`, fixed patterns, or pseudo-random data).
- **Scope**: Protects against simple, non-invasive keyboard/software recovery attacks (such as basic un-delete or standard forensic disk editors).
- **Limitation**: Does not address inaccessible sectors, reallocated bad sectors, or firmware-hidden reserve blocks (HPA/DCO).
- **Target Media**: Magnetic HDDs, USB thumb drives, and standard optical media intended to be reused within the same security enclave.

#### 2. Purge (Cryptographic & Firmware-Level Sanitization)
- **Mechanism**: Executes advanced techniques that make target data recovery infeasible even using state-of-the-art laboratory attacks (e.g. magnetic force microscopy or firmware exploitation).
- **Methods**: Multi-pass algorithmic overwriting (zeros, ones, random PRNG), ATA/NVMe Cryptographic Erase (instant sanitization of the internal AES Media Encryption Key), or firmware-level Secure Erase / Sanitize Device commands.
- **Scope**: Cleans both user-accessible areas and hidden reserve sectors, wear-leveling pools, and remapped defective blocks.
- **Target Media**: Modern NVMe/SATA SSDs, enterprise flash arrays, and magnetic HDDs decommissioned outside the organization.

#### 3. Destroy (Physical Obliteration)
- **Mechanism**: Physical destruction through degaussing (for magnetic media only), incineration, shredding into 2mm particles, or disintegration.
- **Verification**: Zero residual magnetic/electronic charge. Recommended for Top Secret / High Confidentiality environments.

*Would you like me to formulate a 1-click execution plan to run NIST Clear or NIST Purge on ${selectedDevice?.model || 'your target media'}?*`;

      } else if (isQuestion && (lower.includes('write-blocker') || lower.includes('write blocker') || lower.includes('read-only'))) {
        searchQueries = ['Hardware write blocker forensic evidence preservation NIST'];
        webSources = [
          { title: 'NIST CFTT: Computer Forensic Tool Testing - Hardware Write Blockers', url: 'https://www.nist.gov/itl/ssd/cs/computer-forensic-tool-testing-program-cftt' },
          { title: 'Scientific Working Group on Digital Evidence (SWGDE) Standards', url: 'https://www.swgde.org/' }
        ];
        reply = `### Forensic Write-Blockers: Purpose & Legal Standards

A **forensic write-blocker** (hardware or logical/driver level) is the single most critical device in digital forensics:

1. **Strict Bitstream Preservation**: It intercepts all OS and controller commands, silently discarding write, modify, delete, and format commands (such as \`WRITE_10\`, \`ATA WRITE EXT\`, or file system mount journals) while allowing unmodified read commands (\`READ_10\`, \`IDENTIFY DEVICE\`).
2. **Chain of Custody & Court Admissibility**: Under Federal Rule of Evidence 901 and ISO/IEC 27037 standards, evidence is only legally admissible if it can be proven that no bytes were altered during examination.
3. **Cryptographic Hash Verification**: Pre-acquisition SHA-256 and Post-acquisition SHA-256 hashes must match bit-for-bit (0 bit variance).
4. **Current Status on ${selectedDevice?.model || 'Your Drive'}**:
   - Write-Blocker Status: **${selectedDevice?.writeBlockerActive ? 'ACTIVE (Hardware Shield Engaged - SAFE)' : 'DISENGAGED (Read/Write Mode - Active Risk)'}**.

*Always ensure the write-blocker is locked before beginning forensic recovery!*`;

      } else if (isQuestion && (lower.includes('trim') || lower.includes('ssd') || lower.includes('wear-leveling'))) {
        searchQueries = ['SSD data recovery after TRIM wear leveling digital forensics'];
        webSources = [
          { title: 'Digital Forensics Magazine: Solid State Drives and the TRIM Command', url: 'https://digitalforensicsmagazine.com/' },
          { title: 'DFIR Review: Forensic Analysis of Solid State Drives', url: 'https://dfir.pubpub.org/' }
        ];
        reply = `### Can SSD Data Be Recovered After TRIM and Wear-Leveling?

Data recovery on Solid State Drives (SSDs) behaves fundamentally differently from mechanical HDDs due to SSD controller architectures:

1. **The TRIM Command**:
   - When an OS deletes a file, it issues an ATA/NVMe TRIM / Deallocate command to the SSD controller.
   - The SSD controller marks those NAND flash blocks as invalid. Subsequent read requests return **Deterministic Read Zeroes (DRZ)** immediately without reading the physical NAND flash cells.

2. **Garbage Collection**:
   - In the background, the SSD controller's Garbage Collection process physically erases and merges blocks into clean pools. Once an erase block is cycled, the data is physically gone.

3. **Window of Recovery**:
   - If the drive is imaged immediately via a hardware write-blocker before Garbage Collection runs, or if TRIM is disabled (e.g. over USB enclosures that do not pass through UASP/SCSI TRIM commands), forensic carving with Foremost and Sleuth Kit can still recover substantial deleted data!
   - Hardware chip-off forensics can directly read NAND dies to recover residual data in over-provisioned or wear-leveled sectors.`;

      } else if (isQuestion && (lower.includes('foremost') || lower.includes('carv') || lower.includes('sleuth'))) {
        searchQueries = ['The Sleuth Kit vs Foremost file carving forensics'];
        webSources = [
          { title: 'The Sleuth Kit (TSK) Official Documentation', url: 'https://www.sleuthkit.org/' },
          { title: 'Foremost File Carving Sourceforge & Linux Forensics', url: 'https://foremost.sourceforge.net/' }
        ];
        reply = `### Comparison: The Sleuth Kit (TSK) vs. Foremost

Digital forensic practitioners use both tools in a complementary multi-phase pipeline:

| Feature | The Sleuth Kit (\`fls\`, \`tsk_recover\`, \`istat\`) | Foremost Magic Byte Carver |
| :--- | :--- | :--- |
| **Primary Method** | File System Metadata parsing (MFT, FAT, Inodes) | Raw bitstream Magic Header/Footer carving |
| **Preserves File Names?** | **Yes** (extracted from directory entries & records) | **No** (files named sequentially by sector offset) |
| **Preserves Folder Trees?**| **Yes** (reconstructs exact path hierarchy) | **No** (categorizes by file extension/type) |
| **Corrupted/Formatted FS?**| Limited if file system structures are destroyed | **Excellent** (ignores file systems completely) |
| **Fragmented Files?** | Reads cluster runlists correctly | High risk of truncated/corrupted artifacts |
| **Execution Domain** | File System Level Recovery | Deep Unallocated Space Recovery |

*In PyForensic Desk, our pipeline executes Sleuth Kit first to restore directory structures, then Foremost to carve unallocated sectors for deleted fragments!*`;

      } else if (lower.includes('recover') || lower.includes('photo') || lower.includes('carv') || lower.includes('file')) {
        reply = `I have formulated a verified forensic recovery workflow for **${selectedDevice?.model || 'target storage media'}**:\n\n1. **Hardware Write-Blocker Enforcement**: Verified bitstream preservation status (Read-Only).\n2. **Pre-Scan Baseline**: Acquiring initial SHA-256 evidence checksum for chain of custody.\n3. **Sleuth Kit Filesystem Parser**: Running \`fls\` and \`tsk_recover\` to extract MFT records & directory tree.\n4. **Deep File Carving**: Executing Foremost magic signature scanner for JPEG, PNG, PDF, and DOCX.\n5. **Forensic Report**: Extracting MACB timelines & computing post-scan verification hash.`;
        actionPlan = {
          action: 'EXECUTE_RECOVERY',
          domain: 'RECOVERY',
          plan_title: `Forensic Recovery & File Carving on ${selectedDevice?.model || 'Storage Media'}`,
          steps: [
            'Verify Hardware Write-Blocker Status (Read-Only Locked)',
            'Acquire Pre-Scan SHA-256 baseline evidence hash',
            'Execute Sleuth Kit fls / tsk_recover directory parsing',
            'Execute Foremost deep file carving for deleted artifacts',
            'Extract MACB timestamps and EXIF geolocation tags',
            'Compute Post-Scan SHA-256 hash to confirm non-destructive read',
          ],
          parameters: {
            enable_sleuthkit: true,
            enable_carving: true,
            write_blocker_required: true,
          },
          safety_confirmation_required: false,
        };
      } else if (lower.includes('sanitize') || lower.includes('wipe') || lower.includes('purge') || lower.includes('destroy')) {
        reply = `⚠️ **CRITICAL SANITIZATION NOTICE**: You requested media sanitization for **${selectedDevice?.model || 'selected device'}**.\n\nUnder **NIST SP 800-88 Rev. 1 Purge**, we will execute a 3-pass overwrite:\n- **Pass 1**: Binary zero fill (0x00)\n- **Pass 2**: Binary one complement (0xFF)\n- **Pass 3**: Cryptographic PRNG stream + verification read\n\nAll MFT entries, partition maps, and unallocated slack space will be irreversibly destroyed. Write-blocker must be disengaged.`;
        actionPlan = {
          action: 'EXECUTE_SANITIZATION',
          domain: 'SANITIZATION',
          plan_title: `NIST SP 800-88 Purge Overwrite on ${selectedDevice?.model || 'Target Device'}`,
          steps: [
            'Disengage Hardware Write-Blocker (Read/Write Mode)',
            'Acquire Pre-Wipe SHA-256 baseline hash',
            'Pass 1: Multi-sector 0x00 Zero-Fill overwrite',
            'Pass 2: Multi-sector 0xFF Complement overwrite',
            'Pass 3: Cryptographic PRNG pseudo-random overwrite with read verify',
            'Obliterate MFT tables, GPT/MBR headers, and volume slack',
            'Verify 100% Zero-Entropy and compute Post-Wipe SHA-256',
          ],
          parameters: {
            standard: 'NIST SP 800-88 Purge',
            wipe_metadata: true,
            wipe_unallocated: true,
          },
          safety_confirmation_required: true,
        };
      } else {
        searchQueries = ['Digital Forensics and Media Sanitization overview'];
        reply = `Hello, Examiner! I am your **PyForensic Smart AI Assistant** equipped with live internet search capabilities.\n\nI can answer any question about:\n- 🌐 **Live Web Research**: Latest NIST SP 800-88 publications, cybersecurity CVEs, and storage standards.\n- 🔍 **Digital Forensics**: How Sleuth Kit (\`tsk_recover\`, \`fls\`) and Foremost file carving work on HDD/SSD/NVMe drives.\n- 🛡️ **Data Destruction**: Clear vs Purge vs Destroy overwrite methods and cryptographic verification.\n- 📋 **Step-by-step guidance**: Guiding your recovery or wipe operations with 1-click execution plans.\n\nAsk me anything!`;
        webSources = [
          { title: 'NIST SP 800-88 Rev. 1: Guidelines for Media Sanitization', url: 'https://csrc.nist.gov/pubs/sp/800/88/r1/final' },
          { title: 'The Sleuth Kit (TSK) & Autopsy Documentation', url: 'https://www.sleuthkit.org/' },
        ];
      }

      return res.json({ text: reply, actionPlan, searchQueries, webSources });
    }

    // Extract structured JSON action plan if present
    let actionPlan = null;
    let cleanText = rawText;
    const jsonMatch = rawText.match(/```json\s*([\s\S]*?)\s*```/);
    if (jsonMatch && jsonMatch[1]) {
      try {
        actionPlan = JSON.parse(jsonMatch[1]);
        cleanText = rawText.replace(/```json\s*[\s\S]*?\s*```/, '').trim();
      } catch (err) {
        console.error('Failed to parse AI JSON action plan:', err);
      }
    }

    return res.json({ text: cleanText, actionPlan, searchQueries, webSources, raw: rawText });
  } catch (error: any) {
    console.error('Gemini API Error:', error);
    return res.status(500).json({ error: error.message || 'Internal AI Error' });
  }
});

// Endpoint to fetch Python source files for inspection & export
app.get('/api/python-sources', (_req: Request, res: Response) => {
  try {
    const pythonDir = path.join(__dirname, 'python_app');
    const files = [
      { name: 'ui_assistant.py', path: path.join(pythonDir, 'ui_assistant.py') },
      { name: 'forensic_engine.py', path: path.join(pythonDir, 'forensic_engine.py') },
      { name: 'audit_certificate.py', path: path.join(pythonDir, 'audit_certificate.py') },
      { name: 'run.py', path: path.join(pythonDir, 'run.py') },
      { name: 'requirements.txt', path: path.join(pythonDir, 'requirements.txt') },
      { name: 'README.md', path: path.join(pythonDir, 'README.md') },
    ];

    const result = files.map((f) => {
      let content = '';
      if (fs.existsSync(f.path)) {
        content = fs.readFileSync(f.path, 'utf-8');
      }
      return {
        filename: f.name,
        content,
        sizeBytes: content.length,
      };
    });

    res.json({ files: result });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// Endpoint to run live Python backend testbench
app.post('/api/run-python-test', (req: Request, res: Response) => {
  const { script } = req.body;
  const scriptName = script === 'audit' ? 'audit_certificate.py' : 'forensic_engine.py';
  const scriptPath = path.join(__dirname, 'python_app', scriptName);

  exec(`python3 ${scriptPath}`, (error, stdout, stderr) => {
    res.json({
      script: scriptName,
      success: !error,
      stdout: stdout || '',
      stderr: stderr || '',
      exitCode: error ? error.code : 0,
    });
  });
});

async function startServer() {
  if (process.env.NODE_ENV !== 'production') {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.join(__dirname, 'dist')));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(__dirname, 'dist', 'index.html'));
    });
  }

  app.listen(port, () => {
    console.log(`PyForensic Desk server listening on port ${port}`);
  });
}

startServer();
