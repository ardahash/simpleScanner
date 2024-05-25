import nmap
import requests
from bs4 import BeautifulSoup
import tkinter as tk
from tkinter import messagebox, filedialog
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

class VulnerabilityScanner:
    def __init__(self, master):
        self.master = master
        master.title("Vulnerability Scanner")

        self.label = tk.Label(master, text="Target IP:")
        self.label.pack()

        self.target_entry = tk.Entry(master)
        self.target_entry.pack()

        self.scan_button = tk.Button(master, text="Start Scan", command=self.start_scan)
        self.scan_button.pack()

        self.save_button = tk.Button(master, text="Save Report", command=self.save_report, state=tk.DISABLED)
        self.save_button.pack()

        self.result_text = tk.Text(master, wrap=tk.WORD, height=20, width=60)
        self.result_text.pack()

    def start_scan(self):
        self.target = self.target_entry.get()
        if not self.target:
            messagebox.showerror("Error", "Please enter a target IP.")
            return

        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, "Scanning open ports...\n")
        open_ports = self.scan_open_ports(self.target)
        self.result_text.insert(tk.END, f"Open Ports:\n{open_ports}\n")
        
        self.result_text.insert(tk.END, "Running OpenVAS scan...\n")
        vulns = self.openvas_scan(self.target)
        self.result_text.insert(tk.END, f"Vulnerabilities:\n{vulns}\n")
        
        self.save_button.config(state=tk.NORMAL)

    def scan_open_ports(self, target):
        nm = nmap.PortScanner()
        nm.scan(target, '1-1024')
        open_ports = []
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                lport = nm[host][proto].keys()
                for port in sorted(lport):
                    if nm[host][proto][port]['state'] == 'open':
                        open_ports.append(port)
        return open_ports

    def openvas_scan(self, target):
        # Placeholder for OpenVAS scan implementation
        return "OpenVAS scan not implemented in this example."

    def save_report(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF files", "*.pdf")])
        if file_path:
            self.generate_pdf_report(file_path)
            messagebox.showinfo("Saved", f"Report saved as {file_path}")

    def generate_pdf_report(self, file_path):
        c = canvas.Canvas(file_path, pagesize=letter)
        width, height = letter
        textobject = c.beginText(40, height - 40)
        textobject.setFont("Helvetica", 12)
        
        report_content = self.result_text.get(1.0, tk.END).split('\n')
        for line in report_content:
            textobject.textLine(line)
        
        c.drawText(textobject)
        c.showPage()
        c.save()

if __name__ == "__main__":
    root = tk.Tk()
    app = VulnerabilityScanner(root)
    root.mainloop()
