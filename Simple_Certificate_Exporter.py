import os
import csv
import subprocess
import tkinter as tk
from tkinter import ttk
from tkinter import filedialog, messagebox

class CertificateProcessorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Certificate Processor")
        self.root.geometry("600x400")
        
        # Default paths
        self.default_input = os.path.join(os.environ['USERPROFILE'], 
                                        'AppData', 'Roaming', 'Microsoft', 
                                        'SystemCertificates', 'My', 'Certificates')
        self.default_output = os.path.join(os.environ['USERPROFILE'], 
                                         'Desktop', 'CertificateDetails.csv')
        
        # Variables
        self.input_path = tk.StringVar(value=self.default_input)
        self.output_path = tk.StringVar(value=self.default_output)
        
        # Create main frame
        main_frame = ttk.Frame(root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Input path section
        ttk.Label(main_frame, text="Input Folder Path:").grid(row=0, column=0, sticky=tk.W, pady=5)
        input_entry = ttk.Entry(main_frame, textvariable=self.input_path, width=60)
        input_entry.grid(row=1, column=0, sticky=(tk.W, tk.E), padx=5)
        ttk.Button(main_frame, text="Browse...", command=self.browse_input).grid(row=1, column=1)
        
        # Output path section
        ttk.Label(main_frame, text="Output File Path:").grid(row=2, column=0, sticky=tk.W, pady=5)
        output_entry = ttk.Entry(main_frame, textvariable=self.output_path, width=60)
        output_entry.grid(row=3, column=0, sticky=(tk.W, tk.E), padx=5)
        ttk.Button(main_frame, text="Browse...", command=self.browse_output).grid(row=3, column=1)
        
        # Process button
        ttk.Button(main_frame, text="Process Certificates", 
                  command=self.process_certificates).grid(row=4, column=0, 
                                                        columnspan=2, pady=20)
        
        # Status text
        self.status_text = tk.Text(main_frame, height=10, width=60, wrap=tk.WORD)
        self.status_text.grid(row=5, column=0, columnspan=2, pady=5)
        
        # Scrollbar for status text
        scrollbar = ttk.Scrollbar(main_frame, orient=tk.VERTICAL, 
                                command=self.status_text.yview)
        scrollbar.grid(row=5, column=2, sticky=(tk.N, tk.S))
        self.status_text['yscrollcommand'] = scrollbar.set
        
        # Configure grid weights
        main_frame.columnconfigure(0, weight=1)
        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)

    def browse_input(self):
        folder_path = filedialog.askdirectory(initialdir=self.input_path.get())
        if folder_path:
            self.input_path.set(folder_path)

    def browse_output(self):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            initialfile="CertificateDetails.csv",
            initialdir=os.path.dirname(self.output_path.get()),
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        if file_path:
            self.output_path.set(file_path)

    def log_message(self, message):
        self.status_text.insert(tk.END, message + "\n")
        self.status_text.see(tk.END)
        self.root.update()

    def process_certificates(self):
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

        # Create PowerShell script
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
                
                $output += [PSCustomObject]@{{
                    Subject = $certObject.Subject
                    Issuer = $certObject.Issuer
                    SerialNumber = $certObject.SerialNumber
                    ValidFrom = $certObject.NotBefore.ToString("yyyy-MM-dd HH:mm:ss")
                    ValidTo = $certObject.NotAfter.ToString("yyyy-MM-dd HH:mm:ss")
                    Thumbprint = $certObject.Thumbprint
                    FileName = $cert.Name
                }}
            }}
            catch {{
                Write-Host "Warning: Could not process file $($cert.Name): $_"
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
