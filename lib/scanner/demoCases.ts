/**
 * Represents a pre-coded vulnerable snippet case for demo purposes.
 */
export interface DemoCase {
  /** The unique string key matching a scanner rule ID */
  id: string;
  /** Human-readable display label for the dropdown list */
  name: string;
  /** Expected rule IDs to be triggered by this demo case */
  expectedRuleIds: string[];
  /** The source code templates in supported languages */
  languages: {
    javascript: string;
    typescript: string;
    python: string;
  };
}

export const demoCases: DemoCase[] = [
  {
    id: "hardcoded-secrets",
    name: "Hardcoded API key",
    expectedRuleIds: ["hardcoded-secrets"],
    languages: {
      javascript: `// Javascript - Hardcoded API Key
const apiKey = "sk-proj-aB1c2D3e4F5g6H7i8J9k0L1m2N3o4P5q6R7s8T9u";
const client = new OpenAIClient({ apiKey: apiKey });

console.log("Initialized client with API key.");`,
      typescript: `// TypeScript - Hardcoded API Key
const apiKey: string = "sk-proj-aB1c2D3e4F5g6H7i8J9k0L1m2N3o4P5q6R7s8T9u";
const client: OpenAIClient = new OpenAIClient({ apiKey });`,
      python: `# Python - Hardcoded API Key
AWS_ACCESS_KEY_ID = "AKIA1234567890ABCDEF"
client = boto3.client('s3', aws_access_key_id=AWS_ACCESS_KEY_ID)

print("Connected to S3 bucket.")`
    }
  },
  {
    id: "sql-injection",
    name: "SQL injection",
    expectedRuleIds: ["sql-injection"],
    languages: {
      javascript: `// Javascript - SQL Injection
async function getUser(req, res) {
  const userId = req.query.id;
  // Dangerous string interpolation
  const query = \`SELECT * FROM users WHERE id = \${userId}\`;
  const result = await db.execute(query);
  return res.json(result);
}`,
      typescript: `// TypeScript - SQL Injection
async function getUser(req: Request, res: Response) {
  const userId = req.query.id;
  const query = \`SELECT * FROM users WHERE id = \${userId}\`;
  const result = await db.execute(query);
  return res.json(result);
}`,
      python: `# Python - SQL Injection
def get_user(request):
    user_id = request.GET.get('id')
    # Dangerous f-string query formatting
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    cursor.execute(query)
    return cursor.fetchall()`
    }
  },
  {
    id: "command-injection",
    name: "Command injection",
    expectedRuleIds: ["command-injection"],
    languages: {
      javascript: `// Javascript - Command Injection
const { exec } = require('child_process');

function pingHost(host) {
  // Dangerous string concatenation in shell execution
  exec("ping -c 1 " + host, (err, stdout, stderr) => {
    console.log(stdout);
  });
}`,
      typescript: `// TypeScript - Command Injection
import { exec } from 'child_process';

function pingHost(host: string): void {
  exec("ping -c 1 " + host, (err, stdout, stderr) => {
    console.log(stdout);
  });
}`,
      python: `# Python - Command Injection
import os

def ping_host(ip):
    # Unsafe shell command execution
    os.system("ping -c 1 " + ip)`
    }
  },
  {
    id: "unsafe-eval",
    name: "Unsafe eval",
    expectedRuleIds: ["unsafe-eval"],
    languages: {
      javascript: `// Javascript - Unsafe Eval
function runCalculation(expr) {
  // Unsafe eval execution
  const result = eval(expr);
  return result;
}`,
      typescript: `// TypeScript - Unsafe Eval
function runCalculation(expr: string): any {
  const result = eval(expr);
  return result;
}`,
      python: `# Python - Unsafe Eval
def run_calculation(expr):
    # Unsafe python eval execution
    return eval(expr)`
    }
  },
  {
    id: "insecure-cors",
    name: "Insecure CORS",
    expectedRuleIds: ["insecure-cors"],
    languages: {
      javascript: `// Javascript - Insecure CORS
const express = require('express');
const cors = require('cors');
const app = express();

// Allowing * with credentials is a critical security vulnerability
app.use(cors({
  origin: "*",
  credentials: true
}));`,
      typescript: `// TypeScript - Insecure CORS
import express from 'express';
import cors from 'cors';
const app = express();

app.use(cors({
  origin: "*",
  credentials: true
}));`,
      python: `# Python - Insecure CORS (Flask)
from flask import Flask
from flask_cors import CORS
app = Flask(__name__)

# Allowing * with credentials is a critical security vulnerability
CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=True)`
    }
  },
  {
    id: "path-traversal",
    name: "Path traversal",
    expectedRuleIds: ["path-traversal"],
    languages: {
      javascript: `// Javascript - Path Traversal
const fs = require('fs');

function getProfile(req, res) {
  const file = req.query.file;
  // Unsanitized filename parameter read directly from queries
  const content = fs.readFileSync(file);
  return res.send(content);
}`,
      typescript: `// TypeScript - Path Traversal
import fs from 'fs';

function getProfile(req: any, res: any) {
  const file = req.query.file;
  const content = fs.readFileSync(file);
  return res.send(content);
}`,
      python: `# Python - Path Traversal
import os

def get_profile(request):
    filename = request.GET.get('filename')
    # Unsanitized path read directly
    with open(filename) as f:
        return f.read()`
    }
  },
  {
    id: "weak-token-generation",
    name: "Weak token generation",
    expectedRuleIds: ["weak-token-generation"],
    languages: {
      javascript: `// Javascript - Weak Token Generation
function generateSessionToken() {
  // Math.random is cryptographically weak and predictable
  const token = Math.random().toString(36).substring(2);
  return token;
}`,
      typescript: `// TypeScript - Weak Token Generation
function generateSessionToken(): string {
  const token: string = Math.random().toString(36).substring(2);
  return token;
}`,
      python: `# Python - Weak Token Generation
import random

def generate_session_token():
    # random module is not cryptographically secure
    session_token = str(random.random())
    return session_token`
    }
  },
  {
    id: "sensitive-logging",
    name: "Sensitive logging",
    expectedRuleIds: ["sensitive-logging"],
    languages: {
      javascript: `// Javascript - Sensitive Logging
console.log("user token:", user.token);`,
      typescript: `// TypeScript - Sensitive Logging
console.log("authorization header", req.headers.authorization);`,
      python: `# Python - Sensitive Logging
import logging
logging.info("password=%s", password)`
    }
  }
];
