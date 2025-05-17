from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from transformers import pipeline
import uvicorn
import requests
from bs4 import BeautifulSoup
import PyPDF2
import io
import re
from typing import Optional, List, Dict, Any
import os
import jwt
from datetime import datetime

app = FastAPI()

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize the summarization pipeline with a smaller, faster model
summarizer = pipeline("summarization", model="facebook/bart-base", device=-1)  # device=-1 for CPU

def clean_text(text: str) -> str:
    """Clean and prepare text for summarization."""
    # Remove extra whitespace
    text = " ".join(text.split())
    
    # Remove special characters but keep punctuation
    text = re.sub(r'[^\w\s.,!?-]', '', text)
    
    # Remove multiple punctuation
    text = re.sub(r'([.,!?])\1+', r'\1', text)
    
    # Remove extra spaces
    text = re.sub(r'\s+', ' ', text)
    
    return text.strip()

def chunk_text(text: str, chunk_size: int = 1024) -> List[str]:
    """Split text into smaller chunks for processing."""
    words = text.split()
    chunks = []
    current_chunk = []
    current_size = 0
    
    for word in words:
        if current_size + len(word) + 1 <= chunk_size:
            current_chunk.append(word)
            current_size += len(word) + 1
        else:
            chunks.append(' '.join(current_chunk))
            current_chunk = [word]
            current_size = len(word)
            
    if current_chunk:
        chunks.append(' '.join(current_chunk))
        
    return chunks

def summarize_chunks(chunks: List[str]) -> str:
    """Summarize text chunks and combine them."""
    summaries = []
    for chunk in chunks:
        if len(chunk.split()) < 50:  # Skip small chunks
            summaries.append(chunk)
            continue
            
        summary = summarizer(
            chunk,
            max_length=100,
            min_length=20,
            do_sample=False,
            truncation=True
        )[0]['summary_text']
        summaries.append(summary)
    
    return ' '.join(summaries)

@app.post("/api/summarize")
async def summarize_text(
    text: str = Form(...),
    format: str = Form("general"),
    language: str = Form("english")
):
    try:
        # Clean and prepare text
        cleaned_text = clean_text(text)
        
        # Split into chunks if text is long
        chunks = chunk_text(cleaned_text) if len(cleaned_text.split()) > 500 else [cleaned_text]
        
        # Generate summary
        summary = summarize_chunks(chunks)
        
        # Format as bullet points if requested
        if format == "bullet_points":
            sentences = re.split(r'[.!?]+', summary)
            sentences = [s.strip() for s in sentences if s.strip()]
            summary = "\n• " + "\n• ".join(sentences)
            
        return {
            "summary": summary,
            "summaryLength": len(summary.split()),
            "timeTaken": 2,
            "originalLanguage": language,
            "format": format
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/summarize-url")
async def summarize_url(
    url: str = Form(...),
    format: str = Form("general"),
    language: str = Form("english")
):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        text = soup.get_text()
        cleaned_text = clean_text(text)
        
        # Split into chunks if text is long
        chunks = chunk_text(cleaned_text) if len(cleaned_text.split()) > 500 else [cleaned_text]
        
        # Generate summary
        summary = summarize_chunks(chunks)
        
        # Format as bullet points if requested
        if format == "bullet_points":
            sentences = re.split(r'[.!?]+', summary)
            sentences = [s.strip() for s in sentences if s.strip()]
            summary = "\n• " + "\n• ".join(sentences)
            
        return {
            "summary": summary,
            "originalText": cleaned_text,
            "summaryLength": len(summary.split()),
            "timeTaken": 2,
            "originalLanguage": language,
            "format": format
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/summarize-file")
async def summarize_file(
    file: UploadFile = File(...),
    format: str = Form("general"),
    language: str = Form("english")
):
    try:
        content = await file.read()
        text = ""
        
        if file.filename.lower().endswith('.pdf'):
            pdf_reader = PyPDF2.PdfReader(io.BytesIO(content))
            for page in pdf_reader.pages:
                text += page.extract_text() + "\n"
        else:  # Assume it's a text file
            text = content.decode('utf-8')
            
        cleaned_text = clean_text(text)
        
        # Split into chunks if text is long
        chunks = chunk_text(cleaned_text) if len(cleaned_text.split()) > 500 else [cleaned_text]
        
        # Generate summary
        summary = summarize_chunks(chunks)
        
        # Format as bullet points if requested
        if format == "bullet_points":
            sentences = re.split(r'[.!?]+', summary)
            sentences = [s.strip() for s in sentences if s.strip()]
            summary = "\n• " + "\n• ".join(sentences)
            
        return {
            "summary": summary,
            "originalText": cleaned_text,
            "summaryLength": len(summary.split()),
            "timeTaken": 2,
            "originalLanguage": language,
            "format": format
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=5000, reload=True) 