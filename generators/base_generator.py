"""Base class for all report generators"""
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, Any
from formatters.pdf_formatter import PDFReportFormatter
from ai.narrative_generator import NarrativeGenerator


class BaseReportGenerator(ABC):
    def __init__(self):
        self.pdf = PDFReportFormatter(output_dir="reports")
        self.ai  = NarrativeGenerator()
        self.generated_at = datetime.utcnow()

    @property
    @abstractmethod
    def report_name(self) -> str:
        pass

    @property
    @abstractmethod
    def schedule(self) -> str:
        """daily / weekly / monthly"""
        pass

    @abstractmethod
    def collect_data(self) -> Dict[str, Any]:
        pass

    @abstractmethod
    def build_sections(self, data: Dict[str, Any]) -> list:
        pass

    def generate(self, output_dir: str = None) -> str:
        if output_dir:
            self.pdf.output_dir = output_dir
            import os
            os.makedirs(output_dir, exist_ok=True)
        data = self.collect_data()
        sections = self.build_sections(data)
        safe_name = self.report_name.lower().replace(' ', '_').replace('/', '_').replace('\\', '_')
        filename = f"{safe_name}_{self.generated_at.strftime('%Y%m%d_%H%M')}.pdf"
        path = self.pdf.generate(filename, self.report_name, sections)
        print(f"  Generated: {path}")
        return path
