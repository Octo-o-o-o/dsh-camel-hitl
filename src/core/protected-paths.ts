import path from 'node:path'
import type { ProtectedPathVerdict } from './types.js'

interface ProtectedRule {
  readonly id: string
  readonly description: string
  readonly test: (normalizedPosixPath: string, baseName: string) => boolean
}

const DEFAULT_PROTECTED_RULES: readonly ProtectedRule[] = [
  {
    id: 'dsh-credentials',
    description: 'DSH credential store (.credentials.yaml)',
    test: (_p, base) => base === '.credentials.yaml' || base === '.credentials.yml',
  },
  {
    id: 'dotenv-secrets',
    description: 'Environment secret files (.env / .env.*)',
    test: (_p, base) => /^\.env(?:\..+)?$/i.test(base) && !/\.example$/i.test(base) && !/\.sample$/i.test(base),
  },
  {
    id: 'ssh-private-keys',
    description: 'SSH keys and authorized_keys (~/.ssh/*)',
    test: (p, base) =>
      /(?:^|\/)\.ssh\/(?:id_[^/]+|authorized_keys|config)$/i.test(p) ||
      (/^id_(?:rsa|ed25519|ecdsa|dsa)$/i.test(base) && !base.endsWith('.pub')),
  },
  {
    id: 'cloud-cli-creds',
    description: 'Cloud/package credentials (.aws/credentials, .kube/config, .npmrc, .netrc, .gnupg)',
    test: (p, base) =>
      /(?:^|\/)\.aws\/credentials$/i.test(p) ||
      /(?:^|\/)\.kube\/config$/i.test(p) ||
      /(?:^|\/)\.gnupg(?:\/|$)/i.test(p) ||
      base === '.npmrc' ||
      base === '.netrc' ||
      base === '.pypirc',
  },
  {
    id: 'private-key-material',
    description: 'Private key & keystore containers (*.pem, *.key, *.p12, *.pfx, *.jks)',
    test: (_p, base) => /\.(?:pem|key|p12|pfx|jks|kdbx)$/i.test(base),
  },
  {
    id: 'audit-ledger-db',
    description: 'Tamper-evident audit database (governance/audit.sqlite*)',
    test: (p) => /(?:^|\/)governance\/audit\.sqlite(?:-wal|-shm)?$/i.test(p),
  },
]

const PATH_KEY_RE = /(?:^|_)(?:path|file|filepath|source|src|dest|destination|target|output|outpath|cwd|dir|directory|vault)$/i

function normalizePosix(raw: string): string {
  return raw.replace(/\\/g, '/').replace(/\/+/g, '/')
}

function extractCandidateStrings(value: unknown, out: string[], depth = 0): void {
  if (!value || depth > 5) return
  if (typeof value === 'string') {
    if (value.length > 0 && value.length <= 2048) out.push(value)
    return
  }
  if (Array.isArray(value)) {
    for (const item of value.slice(0, 64)) extractCandidateStrings(item, out, depth + 1)
    return
  }
  if (typeof value === 'object') {
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (PATH_KEY_RE.test(k) || k === 'command' || k === 'cmd' || k === 'script') {
        extractCandidateStrings(v, out, depth + 1)
      } else if (typeof v === 'object' && v !== null) {
        extractCandidateStrings(v, out, depth + 1)
      }
    }
  }
}

function tokenizeCommandPaths(text: string): string[] {
  const tokens: string[] = [text]
  for (const part of text.split(/[\s'"`=|;&<>()]+/)) {
    if (part.length >= 2 && (part.includes('/') || part.includes('\\') || part.startsWith('.'))) {
      tokens.push(part)
    }
  }
  return tokens
}

export class ProtectedPathMatcher {
  private readonly normalizedVaultRoots: readonly string[]

  constructor(vaultPaths: readonly string[] = []) {
    this.normalizedVaultRoots = vaultPaths
      .filter((p) => typeof p === 'string' && p.trim().length > 0)
      .map((p) => normalizePosix(path.resolve(p)).replace(/\/$/, '').toLowerCase())
  }

  getRulesSummary(): readonly string[] {
    return [
      ...DEFAULT_PROTECTED_RULES.map((r) => `${r.id}: ${r.description}`),
      ...this.normalizedVaultRoots.map((v, i) => `vault-${i + 1}: ${v}`),
    ]
  }

  checkArguments(args: unknown): ProtectedPathVerdict {
    const rawStrings: string[] = []
    extractCandidateStrings(args, rawStrings)

    for (const raw of rawStrings) {
      for (const token of tokenizeCommandPaths(raw)) {
        const norm = normalizePosix(token)
        const base = path.posix.basename(norm)
        for (const rule of DEFAULT_PROTECTED_RULES) {
          if (rule.test(norm, base)) {
            return {
              blocked: true,
              matchedPath: norm,
              matchedRule: rule.id,
              reason: `Protected path blocked by monotonic guard (${rule.id}): ${rule.description}`,
            }
          }
        }
        if (this.normalizedVaultRoots.length > 0) {
          const resolved = normalizePosix(path.resolve(token)).replace(/\/$/, '').toLowerCase()
          for (const vaultRoot of this.normalizedVaultRoots) {
            if (resolved === vaultRoot || resolved.startsWith(`${vaultRoot}/`)) {
              return {
                blocked: true,
                matchedPath: norm,
                matchedRule: 'vault-path',
                reason: `Vault directory access blocked by monotonic guard`,
              }
            }
          }
        }
      }
    }

    return { blocked: false }
  }
}
