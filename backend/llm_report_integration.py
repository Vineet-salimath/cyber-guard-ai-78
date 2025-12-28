#!/usr/bin/env python3
"""
LLM Integration Module - Connect report cleaner to LLM APIs
Provides interfaces for OpenAI, Anthropic, and other LLM providers.
"""

import os
import json
import logging
from typing import Optional, Dict, Any
from abc import ABC, abstractmethod
from report_cleaner import ReportCleaner, create_llm_prompt

logger = logging.getLogger(__name__)


class LLMProvider(ABC):
    """Abstract base class for LLM providers."""
    
    @abstractmethod
    def clean_report_with_llm(self, raw_report: str) -> str:
        """
        Clean a report using LLM.
        
        Args:
            raw_report: Raw malware report with potential junk characters
            
        Returns:
            Cleaned markdown formatted report
        """
        pass


class OpenAIProvider(LLMProvider):
    """OpenAI API integration for report cleaning."""
    
    def __init__(self, api_key: Optional[str] = None, model: str = "gpt-4-turbo-preview"):
        """
        Initialize OpenAI provider.
        
        Args:
            api_key: OpenAI API key (defaults to OPENAI_API_KEY env var)
            model: Model to use (defaults to gpt-4-turbo-preview)
        """
        self.api_key = api_key or os.getenv('OPENAI_API_KEY')
        self.model = model
        
        if not self.api_key:
            raise ValueError("OpenAI API key not provided. Set OPENAI_API_KEY environment variable.")
        
        try:
            import openai
            openai.api_key = self.api_key
            self.client = openai.OpenAI(api_key=self.api_key)
        except ImportError:
            raise ImportError("openai package required. Install with: pip install openai")
    
    def clean_report_with_llm(self, raw_report: str) -> str:
        """
        Clean report using OpenAI API.
        
        Args:
            raw_report: Raw report with potential encoding issues
            
        Returns:
            Cleaned markdown report
        """
        try:
            system_prompt = create_llm_prompt()
            
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": system_prompt
                    },
                    {
                        "role": "user",
                        "content": f"Please clean and format this security report:\n\n{raw_report}"
                    }
                ],
                temperature=0.2,  # Low temperature for consistent formatting
                max_tokens=4096
            )
            
            cleaned_report = response.choices[0].message.content
            logger.info("Report cleaned successfully with OpenAI")
            return cleaned_report
            
        except Exception as e:
            logger.error(f"Error cleaning report with OpenAI: {e}")
            raise


class AnthropicProvider(LLMProvider):
    """Anthropic Claude API integration for report cleaning."""
    
    def __init__(self, api_key: Optional[str] = None, model: str = "claude-3-opus-20240229"):
        """
        Initialize Anthropic provider.
        
        Args:
            api_key: Anthropic API key (defaults to ANTHROPIC_API_KEY env var)
            model: Model to use (defaults to claude-3-opus)
        """
        self.api_key = api_key or os.getenv('ANTHROPIC_API_KEY')
        self.model = model
        
        if not self.api_key:
            raise ValueError("Anthropic API key not provided. Set ANTHROPIC_API_KEY environment variable.")
        
        try:
            from anthropic import Anthropic
            self.client = Anthropic(api_key=self.api_key)
        except ImportError:
            raise ImportError("anthropic package required. Install with: pip install anthropic")
    
    def clean_report_with_llm(self, raw_report: str) -> str:
        """
        Clean report using Anthropic Claude API.
        
        Args:
            raw_report: Raw report with potential encoding issues
            
        Returns:
            Cleaned markdown report
        """
        try:
            system_prompt = create_llm_prompt()
            
            response = self.client.messages.create(
                model=self.model,
                max_tokens=4096,
                system=system_prompt,
                messages=[
                    {
                        "role": "user",
                        "content": f"Please clean and format this security report:\n\n{raw_report}"
                    }
                ]
            )
            
            cleaned_report = response.content[0].text
            logger.info("Report cleaned successfully with Anthropic Claude")
            return cleaned_report
            
        except Exception as e:
            logger.error(f"Error cleaning report with Anthropic: {e}")
            raise


class HybridReportCleaner:
    """
    Hybrid approach: Uses LLM when available, falls back to rule-based cleaner.
    """
    
    def __init__(self, llm_provider: Optional[LLMProvider] = None):
        """
        Initialize hybrid cleaner.
        
        Args:
            llm_provider: Optional LLM provider (OpenAI, Anthropic, etc.)
                         If None, uses rule-based cleaning only
        """
        self.llm_provider = llm_provider
        self.rule_based_cleaner = ReportCleaner()
    
    def clean_report(self, raw_report: str, use_llm: bool = True) -> Dict[str, Any]:
        """
        Clean a report using LLM if available, or rule-based approach.
        
        Args:
            raw_report: Raw malware report
            use_llm: Whether to attempt LLM-based cleaning (falls back to rule-based)
            
        Returns:
            Dictionary with cleaned data and metadata
        """
        result = {
            'success': False,
            'method': None,
            'cleaned_report': None,
            'structured_data': None,
            'error': None
        }
        
        # Try LLM approach first if available and requested
        if use_llm and self.llm_provider:
            try:
                cleaned_markdown = self.llm_provider.clean_report_with_llm(raw_report)
                
                # Also get structured data from rule-based cleaner
                structured = self.rule_based_cleaner.process_report(raw_report)
                
                result['success'] = True
                result['method'] = 'LLM-based (with rule-based fallback)'
                result['cleaned_report'] = cleaned_markdown
                result['structured_data'] = {
                    k: v for k, v in structured.items() 
                    if k not in ['cleaned_text', 'original_length', 'cleaned_length']
                }
                
                logger.info("Report cleaned using hybrid approach (LLM primary)")
                return result
                
            except Exception as e:
                logger.warning(f"LLM cleaning failed, falling back to rule-based: {e}")
                result['error'] = f"LLM failed: {str(e)}"
        
        # Fallback to rule-based cleaner
        try:
            structured = self.rule_based_cleaner.process_report(raw_report)
            markdown = self.rule_based_cleaner.format_as_markdown(structured)
            
            result['success'] = True
            result['method'] = 'Rule-based'
            result['cleaned_report'] = markdown
            result['structured_data'] = {
                k: v for k, v in structured.items() 
                if k not in ['cleaned_text', 'original_length', 'cleaned_length']
            }
            
            if result['error']:
                result['error'] += " (fell back to rule-based successfully)"
            
            logger.info("Report cleaned using rule-based approach")
            return result
            
        except Exception as e:
            result['success'] = False
            result['method'] = 'All methods failed'
            result['error'] = str(e)
            logger.error(f"All cleaning methods failed: {e}")
            return result


def get_llm_provider(provider_name: str = 'auto') -> Optional[LLMProvider]:
    """
    Get appropriate LLM provider based on available credentials.
    
    Args:
        provider_name: 'openai', 'anthropic', or 'auto' (tries both in order)
        
    Returns:
        Initialized LLM provider or None if unavailable
    """
    if provider_name in ['openai', 'auto']:
        if os.getenv('OPENAI_API_KEY'):
            try:
                return OpenAIProvider()
            except Exception as e:
                logger.warning(f"Could not initialize OpenAI provider: {e}")
    
    if provider_name in ['anthropic', 'auto']:
        if os.getenv('ANTHROPIC_API_KEY'):
            try:
                return AnthropicProvider()
            except Exception as e:
                logger.warning(f"Could not initialize Anthropic provider: {e}")
    
    return None


# Integration examples

def example_usage_with_file():
    """Example: Load report from file and clean it."""
    
    # Get LLM provider if available
    llm = get_llm_provider('auto')
    
    # Create hybrid cleaner
    cleaner = HybridReportCleaner(llm_provider=llm)
    
    # Example: Read raw report from file
    # with open('raw_report.txt', 'r') as f:
    #     raw_report = f.read()
    
    # For demo purposes
    raw_report = """
    Report ID: Ø=malware_scan_001 Date: 2024-01-15
    Threat: https://example.com/malicious.exeþfilename
    
    Antivirus Detection Results: 15/70 þ infected
    Kaspersky | Detection: Trojan.Win32þ.ABC
    Norton | CLEAR | Safe
    AVG | Detection: Generic malware
    """
    
    # Clean the report
    result = cleaner.clean_report(raw_report, use_llm=True)
    
    # Display results
    print(f"Method used: {result['method']}")
    print(f"Success: {result['success']}")
    print("\nCleaned Report:")
    print(result['cleaned_report'])
    
    if result['structured_data']:
        print("\nStructured Data:")
        print(json.dumps(result['structured_data'], indent=2))
    
    return result


def example_integration_with_existing_system():
    """
    Example: Integrate with existing report generation system.
    
    This shows how to add the cleaner to your existing scan reporting pipeline.
    """
    
    # 1. In your scanner route handler or async scanner:
    cleaner = HybridReportCleaner(llm_provider=get_llm_provider('auto'))
    
    # 2. After generating raw report:
    raw_report = "... your raw threat scan report ..."
    
    # 3. Clean it:
    result = cleaner.clean_report(raw_report)
    
    # 4. Use the cleaned report in your API response:
    response = {
        'status': 'success',
        'report': result['cleaned_report'],
        'threat_data': result['structured_data'],
        'method': result['method'],
        'timestamp': '2024-01-15T10:30:00Z'
    }
    
    return response


if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Run example
    print("Running report cleaner example...\n")
    example_usage_with_file()
