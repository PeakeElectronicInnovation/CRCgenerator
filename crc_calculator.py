import tkinter as tk
from tkinter import ttk, messagebox
import crccheck.crc as crc
import binascii

class CRCCalculator:
    def __init__(self, root):
        self.root = root
        self.root.title("CRC Calculator")
        self.root.geometry("800x600")
        
        # CRC configurations with parameters
        self.crc_configs = {
            "Custom": {"class": crc.Crc32, "poly": 0x04C11DB7, "init": 0xFFFFFFFF, "xor_out": 0xFFFFFFFF, "ref_in": True, "ref_out": True},
            "CRC-8": {"class": crc.Crc8, "poly": 0x07, "init": 0x00, "xor_out": 0x00, "ref_in": False, "ref_out": False},
            "CRC-8/CDMA2000": {"class": crc.Crc8Cdma2000, "poly": 0x9B, "init": 0xFF, "xor_out": 0x00, "ref_in": False, "ref_out": False},
            "CRC-8/DARC": {"class": crc.Crc8Darc, "poly": 0x39, "init": 0x00, "xor_out": 0x00, "ref_in": True, "ref_out": True},
            "CRC-8/DVB-S2": {"class": crc.Crc8DvbS2, "poly": 0xD5, "init": 0x00, "xor_out": 0x00, "ref_in": False, "ref_out": False},
            "CRC-16": {"class": crc.Crc16, "poly": 0x8005, "init": 0x0000, "xor_out": 0x0000, "ref_in": True, "ref_out": True},
            "CRC-16/CCITT": {"class": crc.Crc16Ccitt, "poly": 0x1021, "init": 0xFFFF, "xor_out": 0x0000, "ref_in": False, "ref_out": False},
            "CRC-16/MODBUS": {"class": crc.Crc16Modbus, "poly": 0x8005, "init": 0xFFFF, "xor_out": 0x0000, "ref_in": True, "ref_out": True},
            "CRC-32": {"class": crc.Crc32, "poly": 0x04C11DB7, "init": 0xFFFFFFFF, "xor_out": 0xFFFFFFFF, "ref_in": True, "ref_out": True},
            "CRC-32/MPEG-2": {"class": crc.Crc32Mpeg2, "poly": 0x04C11DB7, "init": 0xFFFFFFFF, "xor_out": 0x00000000, "ref_in": False, "ref_out": False}
        }

        self.setup_ui()

    def setup_ui(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # CRC Type Selection
        ttk.Label(main_frame, text="CRC Type:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.crc_type = ttk.Combobox(main_frame, values=list(self.crc_configs.keys()))
        self.crc_type.grid(row=0, column=1, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        self.crc_type.set("Custom")
        self.crc_type.bind('<<ComboboxSelected>>', self.on_crc_change)

        # Custom Parameters Frame
        self.custom_frame = ttk.LabelFrame(main_frame, text="Custom Parameters", padding="5")
        self.custom_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)

        # Polynomial Entry
        ttk.Label(self.custom_frame, text="Polynomial (hex):").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.poly_var = tk.StringVar(value=hex(self.crc_configs["Custom"]["poly"])[2:].upper())
        self.poly_entry = ttk.Entry(self.custom_frame, textvariable=self.poly_var)
        self.poly_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=2)
        self.poly_entry.bind('<KeyRelease>', self.update_custom_params)

        # Initial Value Entry
        ttk.Label(self.custom_frame, text="Initial Value (hex):").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.init_var = tk.StringVar(value=hex(self.crc_configs["Custom"]["init"])[2:].upper())
        self.init_entry = ttk.Entry(self.custom_frame, textvariable=self.init_var)
        self.init_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=2)
        self.init_entry.bind('<KeyRelease>', self.update_custom_params)

        # XOR Out Entry
        ttk.Label(self.custom_frame, text="XOR-out Value (hex):").grid(row=2, column=0, sticky=tk.W, pady=2)
        self.xor_var = tk.StringVar(value=hex(self.crc_configs["Custom"]["xor_out"])[2:].upper())
        self.xor_entry = ttk.Entry(self.custom_frame, textvariable=self.xor_var)
        self.xor_entry.grid(row=2, column=1, sticky=(tk.W, tk.E), pady=2)
        self.xor_entry.bind('<KeyRelease>', self.update_custom_params)

        # Reflect Options
        self.ref_in_var = tk.BooleanVar(value=self.crc_configs["Custom"]["ref_in"])
        self.ref_in_check = ttk.Checkbutton(self.custom_frame, text="Reflect Input", 
                                          variable=self.ref_in_var, command=self.update_custom_params)
        self.ref_in_check.grid(row=3, column=0, sticky=tk.W, pady=2)

        self.ref_out_var = tk.BooleanVar(value=self.crc_configs["Custom"]["ref_out"])
        self.ref_out_check = ttk.Checkbutton(self.custom_frame, text="Reflect Output", 
                                           variable=self.ref_out_var, command=self.update_custom_params)
        self.ref_out_check.grid(row=3, column=1, sticky=tk.W, pady=2)

        # Width Selection
        ttk.Label(self.custom_frame, text="CRC Width:").grid(row=4, column=0, sticky=tk.W, pady=2)
        self.width_var = tk.StringVar(value="32")
        self.width_combo = ttk.Combobox(self.custom_frame, values=["8", "16", "32"], 
                                      textvariable=self.width_var, state="readonly", width=10)
        self.width_combo.grid(row=4, column=1, sticky=tk.W, pady=2)
        self.width_combo.bind('<<ComboboxSelected>>', self.update_custom_params)

        # Input Format Selection
        ttk.Label(main_frame, text="Input Format:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.input_format = ttk.Combobox(main_frame, values=["ASCII", "Hex", "Binary", "Decimal"])
        self.input_format.grid(row=2, column=1, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        self.input_format.set("ASCII")
        self.input_format.bind('<<ComboboxSelected>>', self.calculate_crc)

        # Input Data
        ttk.Label(main_frame, text="Input Data:").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.input_data = tk.Text(main_frame, height=5, width=50)
        self.input_data.grid(row=3, column=1, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        self.input_data.bind('<KeyRelease>', self.calculate_crc)

        # Result
        ttk.Label(main_frame, text="CRC Result:").grid(row=4, column=0, sticky=tk.W, pady=5)
        self.result_hex = ttk.Entry(main_frame, state='readonly')
        self.result_hex.grid(row=4, column=1, columnspan=2, sticky=(tk.W, tk.E), pady=5)

        # Additional Info Frame
        info_frame = ttk.LabelFrame(main_frame, text="CRC Information", padding="5")
        info_frame.grid(row=5, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=10)

        self.info_text = tk.Text(info_frame, height=4, width=50, state='disabled')
        self.info_text.pack(fill=tk.X)

        # Configure grid
        main_frame.columnconfigure(1, weight=1)
        self.custom_frame.columnconfigure(1, weight=1)

        # Update custom frame visibility
        self.update_custom_frame_visibility()

    def parse_input(self, input_str, format_type):
        try:
            if format_type == "ASCII":
                return input_str.encode('ascii')
            elif format_type == "Hex":
                # Remove spaces and 0x prefix if present
                clean_hex = input_str.replace(" ", "").replace("0x", "")
                return bytes.fromhex(clean_hex)
            elif format_type == "Binary":
                # Remove spaces and 0b prefix if present
                clean_bin = input_str.replace(" ", "").replace("0b", "")
                return int(clean_bin, 2).to_bytes((len(clean_bin) + 7) // 8, byteorder='big')
            elif format_type == "Decimal":
                # Convert comma-separated decimals to bytes
                numbers = [int(x.strip()) for x in input_str.split(',')]
                return bytes(numbers)
        except Exception as e:
            return None

    def calculate_crc(self, event=None):
        input_str = self.input_data.get("1.0", tk.END).strip()
        if not input_str:
            self.result_hex.configure(state='normal')
            self.result_hex.delete(0, tk.END)
            self.result_hex.configure(state='readonly')
            return

        data = self.parse_input(input_str, self.input_format.get())
        if data is None:
            self.result_hex.configure(state='normal')
            self.result_hex.delete(0, tk.END)
            self.result_hex.insert(0, "Invalid input format")
            self.result_hex.configure(state='readonly')
            return

        try:
            crc_class = self.crc_configs[self.crc_type.get()]["class"]
            crc_calculator = crc_class()
            result = crc_calculator.calc(data)
            
            # Format result based on CRC type
            if "CRC-8" in self.crc_type.get():
                result_str = f"0x{result:02X}"
            elif "CRC-16" in self.crc_type.get():
                result_str = f"0x{result:04X}"
            else:
                result_str = f"0x{result:08X}"

            self.result_hex.configure(state='normal')
            self.result_hex.delete(0, tk.END)
            self.result_hex.insert(0, result_str)
            self.result_hex.configure(state='readonly')

        except Exception as e:
            self.result_hex.configure(state='normal')
            self.result_hex.delete(0, tk.END)
            self.result_hex.insert(0, f"Error: {str(e)}")
            self.result_hex.configure(state='readonly')

    def update_custom_params(self, event=None):
        try:
            # Get values from entries and convert from hex
            poly = int(self.poly_var.get(), 16)
            init = int(self.init_var.get(), 16)
            xor_out = int(self.xor_var.get(), 16)
            
            # Get reflection settings
            ref_in = self.ref_in_var.get()
            ref_out = self.ref_out_var.get()
            
            # Get width and set appropriate CRC class
            width = int(self.width_var.get())
            if width == 8:
                crc_class = crc.Crc8
            elif width == 16:
                crc_class = crc.Crc16
            else:  # width == 32
                crc_class = crc.Crc32
            
            # Update custom configuration
            self.crc_configs["Custom"] = {
                "class": crc_class,
                "poly": poly,
                "init": init,
                "xor_out": xor_out,
                "ref_in": ref_in,
                "ref_out": ref_out
            }
            
            # Update display
            if self.crc_type.get() == "Custom":
                self.calculate_crc()
                self.on_crc_change()
        except ValueError:
            # Invalid hex value entered, ignore
            pass

    def update_custom_frame_visibility(self):
        if self.crc_type.get() == "Custom":
            self.custom_frame.grid()
        else:
            self.custom_frame.grid_remove()

    def on_crc_change(self, event=None):
        self.update_custom_frame_visibility()
        self.calculate_crc()
        crc_config = self.crc_configs[self.crc_type.get()]
        
        # Update info text
        self.info_text.configure(state='normal')
        self.info_text.delete("1.0", tk.END)
        info = f"Polynomial: 0x{crc_config['poly']:X}\n"
        info += f"Initial Value: 0x{crc_config['init']:X}\n"
        info += f"XOR-out Value: 0x{crc_config['xor_out']:X}\n"
        info += f"Reflect Input: {crc_config['ref_in']}, Reflect Output: {crc_config['ref_out']}"
        self.info_text.insert("1.0", info)
        self.info_text.configure(state='disabled')

if __name__ == "__main__":
    root = tk.Tk()
    app = CRCCalculator(root)
    root.mainloop()
