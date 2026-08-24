"""
Data Provenance Tracking Module.

Tracks origin of all content and enforces data vs. instruction separation.
"""

from typing import List, Dict, Optional
from security_types import (
    Provenance, TokenProvenance, PromptSegment, AuthorityLevel,
    StructuredPrompt
)
from datetime import datetime


class ProvenanceTracker:
    """Tracks and manages data provenance for all content."""
    
    def __init__(self):
        self.provenance_registry: Dict[str, Provenance] = {}
    
    def create_provenance(
        self,
        source: str,
        authority: AuthorityLevel,
        metadata: Optional[Dict] = None,
        parent: Optional[Provenance] = None
    ) -> Provenance:
        """
        Create a new provenance record.
        
        Args:
            source: Source identifier (e.g., "user_input", "web_scrape")
            authority: Authority level of the source
            metadata: Additional metadata
            parent: Parent provenance if this is derived/transformed content
            
        Returns:
            Provenance object
        """
        provenance = Provenance(
            source=source,
            authority=authority,
            timestamp=datetime.now(),
            metadata=metadata or {},
            parent_provenance=parent
        )
        
        # Register for tracking
        provenance_id = f"{source}_{provenance.timestamp.timestamp()}"
        self.provenance_registry[provenance_id] = provenance
        
        return provenance
    
    def tag_external_content(
        self,
        content: str,
        source_url: Optional[str] = None,
        retrieval_method: Optional[str] = None
    ) -> PromptSegment:
        """
        Tag external/untrusted content with appropriate provenance.
        
        External content is ALWAYS treated as data, never executable instructions.
        """
        provenance = self.create_provenance(
            source="external_untrusted",
            authority=AuthorityLevel.EXTERNAL_UNTRUSTED,
            metadata={
                "source_url": source_url,
                "retrieval_method": retrieval_method,
                "is_web_content": source_url is not None
            }
        )
        
        return PromptSegment(
            content=content,
            provenance=provenance,
            authority=AuthorityLevel.EXTERNAL_UNTRUSTED,
            is_executable=False  # External content is NEVER executable
        )
    
    def tag_user_input(
        self,
        content: str,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None
    ) -> PromptSegment:
        """Tag authenticated user input."""
        provenance = self.create_provenance(
            source="user_input",
            authority=AuthorityLevel.USER,
            metadata={
                "user_id": user_id,
                "session_id": session_id
            }
        )
        
        return PromptSegment(
            content=content,
            provenance=provenance,
            authority=AuthorityLevel.USER,
            is_executable=False  # Will be determined by risk analysis
        )
    
    def tag_memory_content(
        self,
        content: str,
        memory_id: Optional[str] = None,
        original_provenance: Optional[Provenance] = None
    ) -> PromptSegment:
        """
        Tag content retrieved from memory.
        
        Memory content inherits authority from original source but may
        be flagged if original was untrusted.
        """
        # If we have original provenance, inherit its authority
        if original_provenance:
            authority = original_provenance.authority
            parent = original_provenance
        else:
            # Unknown origin - treat as untrusted
            authority = AuthorityLevel.EXTERNAL_UNTRUSTED
            parent = None
        
        provenance = self.create_provenance(
            source="memory",
            authority=authority,
            metadata={"memory_id": memory_id},
            parent=parent
        )
        
        return PromptSegment(
            content=content,
            provenance=provenance,
            authority=authority,
            is_executable=False  # Memory content needs re-validation
        )
    
    def get_provenance_chain(self, provenance: Provenance) -> List[Provenance]:
        """Get full provenance chain (for audit trail)."""
        chain = [provenance]
        current = provenance.parent_provenance
        
        while current:
            chain.append(current)
            current = current.parent_provenance
        
        return chain
    
    def enforce_data_vs_instruction_separation(
        self,
        prompt: StructuredPrompt
    ) -> StructuredPrompt:
        """
        Enforce rule: untrusted text is data, never executable instructions.
        
        This is a critical security boundary.
        """
        sanitized_segments = []
        
        for segment in prompt.segments:
            # External untrusted content is ALWAYS data
            if segment.authority == AuthorityLevel.EXTERNAL_UNTRUSTED:
                sanitized_segment = PromptSegment(
                    content=segment.content,
                    provenance=segment.provenance,
                    authority=segment.authority,
                    is_executable=False  # Force to data-only
                )
                sanitized_segments.append(sanitized_segment)
            else:
                # Other segments keep their is_executable flag
                sanitized_segments.append(segment)
        
        return StructuredPrompt(
            segments=sanitized_segments,
            system_instructions=prompt.system_instructions,
            developer_policies=prompt.developer_policies,
            user_input=prompt.user_input,
            external_content=prompt.external_content,
            full_text=prompt.full_text
        )
    
    def audit_provenance(self, prompt: StructuredPrompt) -> Dict:
        """Generate audit report of provenance for all segments."""
        audit = {
            "total_segments": len(prompt.segments),
            "authority_distribution": {},
            "untrusted_sources": [],
            "provenance_chains": []
        }
        
        for segment in prompt.segments:
            authority = segment.authority.name
            audit["authority_distribution"][authority] = \
                audit["authority_distribution"].get(authority, 0) + 1
            
            if segment.authority == AuthorityLevel.EXTERNAL_UNTRUSTED:
                audit["untrusted_sources"].append({
                    "source": segment.provenance.source,
                    "metadata": segment.provenance.metadata
                })
            
            chain = self.get_provenance_chain(segment.provenance)
            audit["provenance_chains"].append({
                "segment_length": len(segment.content),
                "chain_length": len(chain),
                "sources": [p.source for p in chain]
            })
        
        return audit

