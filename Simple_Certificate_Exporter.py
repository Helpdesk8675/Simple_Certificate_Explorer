import os
import csv
import logging
import subprocess
import tkinter as tk
from typing import Optional, List, Dict
from datetime import datetime
from pathlib import Path
from tkinter import ttk, filedialog, messagebox
from dataclasses import dataclass

# Simple_certificate_exporter.py
#
# This script provides a utility to extract certificate details from a specified folder
# and export them to a CSV file. It supports both PEM and DER encoded certificates
# and can process files recursively within the folder.

# Features:
# - Recursive search for certificate files.
# - Support for PEM and DER encoding formats.
# - Export details like Subject, Issuer, Serial Number, Thumbprint, and validity dates.

# Usage:
# - Run the script directly to launch a GUI for selecting input and output folders.
# - Alternatively, integrate the functions into other scripts for customized workflows.

# Dependencies:
# - cryptography >= 3.0
# - tkinter (standard Python library)

# Author: helpdesk8675

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='certificate_processor.log'
)

@dataclass
class CertificateConfig:
    """Configuration settings for certificate processing"""
    allowed_extensions: List[str] = None
    verify_chain: bool = False
    check_revocation: bool = False
    export_format: str = "csv"

class CertificateProcessor:
    """Handles certificate processing logic separate from GUI"""
    
    def __init__(self, config: CertificateConfig):
        self.config = config
        self.processed_certs: List[Dict] = []

    def validate_path(self, path: str) -> bool:
        """Validate file path for security"""
        try:
            resolved_path = Path(path).resolve()
            return resolved_path.exists()
        except (RuntimeError, OSError):
            return False

    def process_certificates(self, input_path: str, output_path: str) -> bool:
        """Process certificates with enhanced security and validation"""
        if not self.validate_path(input_path):
            raise ValueError("Invalid or inaccessible input path")

        # Generate sanitized PowerShell script
        ps_script = self._generate_ps_script(input_path, output_path)
        script_path = self._save_temp_script(ps_script)

        try:
            return self._execute_ps_script(script_path)
        finally:
            self._cleanup_temp_file(script_path)

    def _generate_ps_script(self, input_path: str, output_path: str) -> str:
        """Generate PowerShell script with sanitized inputs"""
        # Sanitize paths for PowerShell
        safe_input_path = input_path.replace('"', '`"')
        safe_output_path = output_path.replace('"', '`"')

        return f'''
        $ErrorActionPreference = "Stop"
        $certPath = "{safe_input_path}"
        $outputPath = "{safe_output_path}"
        
        # Validation
        if (-not (Test-Path $certPath)) {{
            throw "Input path does not exist"
        }}

        $certificates = Get-ChildItem -Path $certPath -File -Recurse
        $output = @()
        $processedCount = 0

        foreach ($cert in $certificates) {{
            try {{
                $certBytes = [System.IO.File]::ReadAllBytes($cert.FullName)
                $certObject = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certBytes)
                
                # Additional validation checks
                if ({str(self.config.verify_chain).lower()}) {{
                    $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
                    $chainValid = $chain.Build($certObject)
                }}
                
                $output += [PSCustomObject]@{{
                    Subject = $certObject.Subject
                    Issuer = $certObject.Issuer
                    SerialNumber = $certObject.SerialNumber
                    ValidFrom = $certObject.NotBefore.ToString("yyyy-MM-dd HH:mm:ss")
                    ValidTo = $certObject.NotAfter.ToString("yyyy-MM-dd HH:mm:ss")
                    Thumbprint = $certObject.Thumbprint
                    FileName = $cert.Name
                    FilePath = $cert.FullName
                    ChainValid = if ({str(self.config.verify_chain).lower()}) {{ $chainValid }} else {{ "Not Checked" }}
                }}
                $processedCount++
                Write-Host "Processed $processedCount certificates..."
            }}
            catch {{
                Write-Host "Warning: Could not process file $($cert.Name): $_"
            }}
        }}

        $output | Export-Csv -Path $outputPath -NoTypeInformation
        Write-Host "Successfully processed $($output.Count) certificates."
        '''

    def _save_temp_script(self, script_content: str) -> str:
        """Save PowerShell script to temporary file"""
        temp_path = Path(os.environ['TEMP']) / f'process_certs_{datetime.now().strftime("%Y%m%d_%H%M%S")}.ps1'
        temp_path.write_text(script_content)
        return str(temp_path)

    def _execute_ps_script(self, script_path: str) -> bool:
        """Execute PowerShell script with proper error handling"""
        try:
            result = subprocess.run(
                ['powershell', '-ExecutionPolicy', 'Bypass', '-File', script_path],
                capture_output=True,
                text=True,
                check=True
            )
            logging.info(f"Script execution successful: {result.stdout}")
            return True
        except subprocess.CalledProcessError as e:
            logging.error(f"Script execution failed: {e.stderr}")
            raise RuntimeError(f"Certificate processing failed: {e.stderr}")

    @staticmethod
    def _cleanup_temp_file(file_path: str) -> None:
        """Clean up temporary files"""
        try:
            os.remove(file_path)
        except OSError as e:
            logging.warning(f"Failed to cleanup temporary file {file_path}: {e}")

class CertificateProcessorGUI:
    """Enhanced GUI with better user feedback and configuration options"""
    
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Certificate Processor by helpdesk8675")
        self.root.geometry("800x600")
        
        # Initialize processor with default config
        self.config = CertificateConfig()
        self.processor = CertificateProcessor(self.config)
        
        # Default paths
        self.default_input = os.path.join(os.environ['USERPROFILE'], 
                                        'AppData', 'Roaming', 'Microsoft', 
                                        'SystemCertificates', 'My', 'Certificates')
        self.default_output = os.path.join(os.environ['USERPROFILE'], 
                                         'Desktop', 'CertificateDetails.csv')
        
        # Variables
        self.input_path = tk.StringVar(value=self.default_input)
        self.output_path = tk.StringVar(value=self.default_output)
        
        self._init_ui()
        
    def _init_ui(self):
        """Initialize the UI with additional configuration options"""
        # Create main frame (only once)
        self.main_frame = ttk.Frame(self.root, padding="10")
        self.main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Input path section
        ttk.Label(self.main_frame, text="Input Folder Path:").grid(row=0, column=0, sticky=tk.W, pady=5)
        input_entry = ttk.Entry(self.main_frame, textvariable=self.input_path, width=60)
        input_entry.grid(row=1, column=0, sticky=(tk.W, tk.E), padx=5)
        ttk.Button(self.main_frame, text="Browse...", command=self.browse_input).grid(row=1, column=1)
        
        # Output path section
        ttk.Label(self.main_frame, text="Output File Path:").grid(row=2, column=0, sticky=tk.W, pady=5)
        output_entry = ttk.Entry(self.main_frame, textvariable=self.output_path, width=60)
        output_entry.grid(row=3, column=0, sticky=(tk.W, tk.E), padx=5)
        ttk.Button(self.main_frame, text="Browse...", command=self.browse_output).grid(row=3, column=1)
        
        # Additional options
        self.verify_chain_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(self.main_frame, text="Verify Certificate Chain", 
                       variable=self.verify_chain_var).grid(row=4, column=0, sticky=tk.W, pady=5)
        
        # Process button
        ttk.Button(self.main_frame, text="Process Certificates", 
                  command=self.process_certificates).grid(row=5, column=0, 
                                                        columnspan=2, pady=20)
        
        # Status text
        self.status_text = tk.Text(self.main_frame, height=10, width=60, wrap=tk.WORD)
        self.status_text.grid(row=6, column=0, columnspan=2, pady=5)
        
        # Scrollbar for status text
        scrollbar = ttk.Scrollbar(self.main_frame, orient=tk.VERTICAL, 
                                command=self.status_text.yview)
        scrollbar.grid(row=6, column=2, sticky=(tk.N, tk.S))
        self.status_text['yscrollcommand'] = scrollbar.set
        
        # Configure grid weights
        self.main_frame.columnconfigure(0, weight=1)
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

    def browse_input(self):
        """Browse for input folder"""
        folder_path = filedialog.askdirectory(initialdir=self.input_path.get())
        if folder_path:
            self.input_path.set(folder_path)

    def browse_output(self):
        """Browse for output file"""
        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            initialfile="CertificateDetails.csv",
            initialdir=os.path.dirname(self.output_path.get()),
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        if file_path:
            self.output_path.set(file_path)

    def log_message(self, message: str) -> None:
        """Add message to status text area"""
        self.status_text.insert(tk.END, message + "\n")
        self.status_text.see(tk.END)
        self.root.update()

    def process_certificates(self):
        """Process certificates with chain verification"""
        # Clear status text
        self.status_text.delete(1.0, tk.END)
        
        # Validate paths
        if not os.path.exists(self.input_path.get()):
            messagebox.showerror("Error", "Input folder does not exist!")
            return
            
        # Create output directory if it doesn't exist
        output_dir = os.path.dirname(self.output_path.get())
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)

        # Create PowerShell script with chain verification
        ps_script = f'''
        $certPath = "{self.input_path.get()}"
        $certificates = Get-ChildItem -Path $certPath -File
        $output = @()

        foreach ($cert in $certificates) {{
            try {{
                $certBytes = [System.IO.File]::ReadAllBytes($cert.FullName)
                $certBase64 = [System.Convert]::ToBase64String($certBytes)
                $certObject = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
                $certObject.Import([System.Convert]::FromBase64String($certBase64))
                
                # Initialize chain verification
                $chain = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Chain
                # Enable revocation checking
                $chain.ChainPolicy.RevocationFlag = [System.Security.Cryptography.X509Certificates.X509RevocationFlag]::EntireChain
                $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::Online
                $chain.ChainPolicy.UrlRetrievalTimeout = New-TimeSpan -Seconds 30
                
                $chainValid = $chain.Build($certObject)
                $chainStatus = @()
                
                if (-not $chainValid) {{
                    foreach ($element in $chain.ChainElements) {{
                        foreach ($status in $element.ChainElementStatus) {{
                            if ($status.Status -ne 'NoError') {{
                                $chainStatus += "Certificate '{0}': {1}" -f $element.Certificate.Subject, $status.StatusInformation
                            }}
                        }}
                    }}
                }}
                
                # Get chain details
                $chainDetails = @()
                foreach ($element in $chain.ChainElements) {{
                    $chainDetails += "Issued By: $($element.Certificate.Issuer)"
                }}
                
                $output += [PSCustomObject]@{{
                    Subject = $certObject.Subject
                    Issuer = $certObject.Issuer
                    SerialNumber = $certObject.SerialNumber
                    ValidFrom = $certObject.NotBefore.ToString("yyyy-MM-dd HH:mm:ss")
                    ValidTo = $certObject.NotAfter.ToString("yyyy-MM-dd HH:mm:ss")
                    Thumbprint = $certObject.Thumbprint
                    FileName = $cert.Name
                    ChainValid = $chainValid
                    ChainStatus = if ($chainStatus) {{ $chainStatus -join "; " }} else {{ "Valid" }}
                    CertificateChain = $chainDetails -join " -> "
                }}
            }}
            catch {{
                Write-Host "Warning: Could not process file $($cert.Name): $_"
            }}
            finally {{
                if ($chain) {{
                    $chain.Dispose()
                }}
            }}
        }}

        $output | Export-Csv -Path "{self.output_path.get()}" -NoTypeInformation
        Write-Host "Processed $($output.Count) certificates."
        '''

        # Save the PowerShell script to a temporary file
        script_path = os.path.join(os.environ['TEMP'], 'process_certs.ps1')
        with open(script_path, 'w') as f:
            f.write(ps_script)

        try:
            # Execute PowerShell script
            self.log_message("Processing certificates...")
            result = subprocess.run(['powershell', '-ExecutionPolicy', 'Bypass', 
                                   '-File', script_path], 
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                self.log_message(result.stdout)
                self.log_message(f"\nCertificate details have been exported to: {self.output_path.get()}")
                messagebox.showinfo("Success", "Certificate processing completed successfully!")
            else:
                self.log_message("Error executing PowerShell script:")
                self.log_message(result.stderr)
                messagebox.showerror("Error", "Failed to process certificates!")
                
        except Exception as e:
            self.log_message(f"Error: {str(e)}")
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
        finally:
            # Clean up temporary script file
            try:
                os.remove(script_path)
            except:
                pass

def main():
    root = tk.Tk()
    app = CertificateProcessorGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
