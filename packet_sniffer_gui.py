import re
import string
import pyshark
import datetime 
import time
import threading
import tkinter as tk
from tkinter import ttk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from tkinter import ttk, scrolledtext, messagebox
from nltk.tokenize import TreebankWordTokenizer
import joblib
import subprocess
import queue
from math import isnan
import math
import hashlib
import asyncio
import os
import csv
from matplotlib.backends.backend_agg import FigureCanvasAgg as FigureCanvas
# === Configuration ===
# Update this path to match your Wireshark installation
# Common paths:
# Windows: r"C:\Program Files\Wireshark\tshark.exe"
# Linux/macOS: "tshark" (if in PATH)
pyshark.tshark.tshark_path = r"C:\Program Files\Wireshark\tshark.exe"  # Adjust this path if needed

# === Globals ===
tokenizer = TreebankWordTokenizer()
captured_packets = []
list_of_packets = []
list_of_counts = []
list_of_classes = []
ml_enabled = True
style_created = False
stats_window_created = False
update_scheduled = False
chart_update_pending = False
pie_update_scheduled = False
bar_update_scheduled = False
table_update_pending = False
ren=0
ii=0
ctt=0
duration = 0
start_time = 0
end_time = 0
current_time = 0
current_view = "pie"  # Default view for statistics
current_interval =0
current_active_interval=0
prev_current_interval = 0
capture_running = False
type_vars = {}
class_vars = {}
protocol_colors = {}
classification_colors = {}

# GUI widget references
stats_win = None
chart_display_frame = None
type_table_body = None
class_table_body = None
interval_buttons = []
total_btn = None

# Statistics tracking
total_packet_type_count = {
    "IPv4": 0, "IPv6": 0, "ARP": 0, "TCP": 0, "UDP": 0,
    "ICMP": 0, "DNS": 0, "HTTP": 0, "HTTPS": 0, "Other": 0
}

classification_count = {}
alert_count = {"Spoofed IP Address": 0, "ARP Spoofing": 0, "ICMP Flood": 0}

capture_stop_event = threading.Event()
capture_thread = None

# Thread-safe queue for GUI updates
packet_queue = queue.Queue()

list_of_summaries = []

try:
    vectorizer, clf = joblib.load('semantic_classifier.pkl')
    test_summary = "TCP src=192.168.1.1 dst=8.8.8.8 port=80"
    vec = vectorizer.transform([test_summary])
    prediction = clf.predict(vec)[0]
    print("ML model loaded successfully")
    #print(f"Prediction: {prediction}, Type: {type(prediction)}")
except Exception as e:
    print(f"ML classification error: {e}")
    print("Continuing without ML model - using rule-based classification only")
    vectorizer = None
    clf = None

# === Utility Functions ===

def initialize_styles():
    global style_created
    style = ttk.Style()
    style.theme_use('clam')

    style.configure('TFrame', background='#0A0A12')
    style.configure('Card.TFrame', background='#161622', relief='raised', borderwidth=1)
    style.configure('TLabel', background='#0A0A12', foreground='#E0E0FF', font=('Segoe UI', 11))
    style.configure('Header.TLabel', font=('Segoe UI Semibold', 13), foreground='#00E5FF')
    style.configure('View.TButton', background='#252538', foreground='#E0E0FF',
                    font=('Segoe UI Semibold', 11), borderwidth=1)
    style.configure('ViewActive.TButton', background='#00E5FF', foreground='#0A0A12',
                    font=('Segoe UI Bold', 11))

    try:
        if not style_created:
            style.element_create('Custom.Checkbutton.indicator', 'from', 'clam')
            style_created = True
    except Exception as e:
        print(f"Style error: {e}")

    style.layout('Custom.TCheckbutton', [
        ('Checkbutton.padding', {'sticky': 'nswe', 'children': [
            ('Checkbutton.indicator', {'side': 'left', 'sticky': ''}),
            ('Checkbutton.focus', {'side': 'left', 'sticky': '', 'children': [
                ('Checkbutton.label', {'sticky': 'nswe'})
            ]})
        ]})
    ])
    style.configure('Custom.TCheckbutton',
        background='#161622',
        foreground='#E0E0FF',
        indicatorbackground='#161622',
        indicatordiameter=20,
        indicatorrelief='raised',
        padding=8,
        borderwidth=2)
    style.map('Custom.TCheckbutton',
        background=[('active', '#252538')],
        foreground=[('active', '#FFFFFF')],
        indicatorcolor=[('selected', '#00E5FF')],
        indicatorrelief=[('selected', 'sunken'), ('!selected', 'raised')])

    style.configure('Interval.TButton', 
        background='#252538', 
        foreground='#E0E0FF',
        font=('Segoe UI Semibold', 11),
        borderwidth=1)
    style.configure('IntervalActive.TButton', 
        background='#00E5FF', 
        foreground='#0A0A12',
        font=('Segoe UI Bold', 11))
    style.configure("IntervalActived.TButton", background="#EB0B0B", foreground="white", padding=6)
    style.configure("IntervalActivedd.TButton", background="#10D809", foreground="white", padding=6)

def open_search_window3():
    search_win = tk.Toplevel(root)
    search_win.title("Packet Search")
    search_win.geometry("800x600")
    search_win.configure(bg='#0A0A12')
    initialize_styles()

    main_frame = ttk.Frame(search_win, style='TFrame')
    main_frame.pack(fill="both", expand=True, padx=20, pady=20)

    header = ttk.Label(main_frame, text="SEARCH PACKETS", style='Header.TLabel')
    header.pack(pady=(0, 10))

    input_frame = ttk.Frame(main_frame, style='Card.TFrame')
    input_frame.pack(fill="x", pady=10)

    search_var = tk.StringVar()

    search_entry = ttk.Entry(input_frame, textvariable=search_var, font=('Segoe UI', 11), width=50)
    search_entry.pack(side="left", padx=(0, 10), pady=10)

    result_count_label = ttk.Label(input_frame, text="", style='TLabel')
    result_count_label.pack(side="left", padx=(10, 0), pady=10)

    results_frame = ttk.Frame(main_frame, style='Card.TFrame')
    results_frame.pack(fill="both", expand=True)

    results_text = tk.Text(results_frame, bg='#161622', fg='#E0E0FF', insertbackground='white',
                           font=('Consolas', 10), wrap="word", relief="flat")
    results_text.pack(fill="both", expand=True, padx=5, pady=5)

    scrollbar = ttk.Scrollbar(results_frame, command=results_text.yview)
    results_text.config(yscrollcommand=scrollbar.set)
    scrollbar.pack(side="right", fill="y")

    last_displayed_results = []

    def run_search(manual=False):
        keyword = search_var.get().strip().lower()
        if not keyword:
            if manual:
                results_text.delete("1.0", tk.END)
                results_text.insert(tk.END, "Please enter a keyword.\n")
                result_count_label.config(text="")
            return

        # Build results list
        current_results = []
        for summary, label in list_of_packets:
            entry = f"{summary}\n→ Classified as: {label}"
            if keyword in summary.lower() or keyword in label.lower():
                current_results.append(entry)

        # Update display only if results changed
        if current_results != last_displayed_results:
            results_text.delete("1.0", tk.END)
            for entry in current_results:
                results_text.insert(tk.END, entry + "\n\n")
            result_count_label.config(text=f"{len(current_results)} result(s)")
            last_displayed_results.clear()
            last_displayed_results.extend(current_results)

    def auto_refresh():
        run_search()
        search_win.after(5000, auto_refresh)  # Repeat every 10 seconds

    # Search button
    ttk.Button(input_frame, text="Search", command=lambda: run_search(manual=True),
               style='ViewActive.TButton').pack(side="left", padx=5)

    # Start auto-refresh loop
    search_win.after(10000, auto_refresh)

def remove_ansi_escape_sequences(text: str) -> str:
    ansi_escape = re.compile(r'\x1b\[[0-9;]*m')
    return ansi_escape.sub('', text)

def show_full_summary():
    global list_of_counts, list_of_classes
    summary_win = tk.Toplevel(root)
    summary_win.title("Packet Capture Analysis Summary")
    summary_win.geometry("850x750")
    summary_win.minsize(700, 600)
    
    # Apply the dark theme styling
    style = ttk.Style()
    style.configure('Summary.TFrame', background='#0A0A12')
    style.configure('Card.TFrame', background='#161622', relief='raised', borderwidth=1)
    style.configure('Summary.TLabel', background='#0A0A12', foreground='#E0E0FF', font=('Segoe UI', 10))
    style.configure('Header.TLabel', font=('Segoe UI Semibold', 11), foreground='#00E5FF')
    style.configure('TCombobox', fieldbackground='#161622', foreground='#FFFFFF', 
                  selectbackground='#00E5FF', selectforeground='#0A0A12',
                  arrowcolor='#00E5FF')

    # Main container with dark theme
    container = ttk.Frame(summary_win, style='Summary.TFrame')
    container.pack(fill=tk.BOTH, expand=True, padx=12, pady=12)

    # Header with title and close button
    header_frame = ttk.Frame(container, style='Card.TFrame')
    header_frame.pack(fill=tk.X, pady=(0, 10), padx=1)
    
    ttk.Label(header_frame, text="PACKET CAPTURE ANALYSIS", 
             font=('Segoe UI Semibold', 12), style='Header.TLabel').pack(side=tk.LEFT, padx=10, pady=6)
    
    ttk.Button(header_frame, text="✕ Close", command=summary_win.destroy, 
              style='Accent.TButton').pack(side=tk.RIGHT, padx=5, pady=3)

    # Interval selection dropdown
    selection_frame = ttk.Frame(container, style='Card.TFrame')
    selection_frame.pack(fill=tk.X, pady=(0, 10))
    
    ttk.Label(selection_frame, text="SELECT INTERVAL:", style='Header.TLabel').pack(side=tk.LEFT, padx=10, pady=8)
    
    interval_var = tk.StringVar()
    intervals = [f"Interval {i}" for i in range(len(list_of_counts))]
    interval_dropdown = ttk.Combobox(selection_frame, textvariable=interval_var, 
                                   values=intervals, state='readonly',
                                   style='TCombobox', font=('Segoe UI', 9))
    interval_dropdown.pack(side=tk.LEFT, padx=(0, 10), pady=5, fill=tk.X, expand=True)
    interval_dropdown.current(0)  # Select first interval by default

    # Selected interval summary display
    selected_frame = ttk.Frame(container, style='Card.TFrame')
    selected_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 15))

    ttk.Label(selected_frame, text="SELECTED INTERVAL SUMMARY", style='Header.TLabel').pack(anchor='w', padx=10, pady=(8, 2))

    selected_summary_text = scrolledtext.ScrolledText(
        selected_frame,
        font=("Consolas", 9),
        height=12,
        wrap=tk.WORD,
        bg='#161622',
        fg='#E0E0FF',
        insertbackground='#00E5FF',
        selectbackground='#FF2D75',
        selectforeground='#FFFFFF',
        bd=0,
        relief='flat',
        padx=8,
        pady=8
    )
    selected_summary_text.pack(fill=tk.BOTH, expand=True, padx=2, pady=(0, 5))
    
    # Total summary section
    total_frame = ttk.Frame(container, style='Card.TFrame')
    total_frame.pack(fill=tk.BOTH, expand=True)

    ttk.Label(total_frame, text="CUMULATIVE TOTAL SUMMARY", style='Header.TLabel').pack(anchor='w', padx=10, pady=(8, 2))

    total_summary_text = scrolledtext.ScrolledText(
        total_frame,
        font=("Consolas", 9),
        height=10,
        wrap=tk.WORD,
        bg='#161622',
        fg='#E0E0FF',
        insertbackground='#00E5FF',
        selectbackground='#FF2D75',
        selectforeground='#FFFFFF',
        bd=0,
        relief='flat',
        padx=8,
        pady=8
    )
    total_summary_text.pack(fill=tk.BOTH, expand=True, padx=2, pady=(0, 5))

    # Function to update the selected interval display
    def update_selected_summary(event=None):
        selected_idx = interval_dropdown.current()
        if selected_idx >= 0 and selected_idx < len(list_of_counts):
            selected_summary_text.config(state='normal')
            selected_summary_text.delete("1.0", tk.END)
            summary_str = format_summary(list_of_counts[selected_idx], list_of_classes[selected_idx], selected_idx)
            selected_summary_text.insert(tk.END, f"────── Interval {selected_idx} ──────\n", 'header')
            selected_summary_text.insert(tk.END, f"{summary_str}\n")
            selected_summary_text.tag_config('header', foreground='#00E5FF')
            selected_summary_text.config(state='disabled')

    # Initialize displays
    update_selected_summary()
    
    total_summary_text.config(state='normal')
    total_summary_text.delete("1.0", tk.END)
    total_summary_text.insert(tk.END, total_format_summary())
    total_summary_text.config(state='disabled')

    # Bind the dropdown selection change
    interval_dropdown.bind("<<ComboboxSelected>>", update_selected_summary)

    # Status bar
    status_frame = ttk.Frame(container, style='Card.TFrame')
    status_frame.pack(fill=tk.X, pady=(10, 0))
    
    ttk.Label(status_frame, text=f"Total Intervals: {len(list_of_counts)} | ", 
             style='Summary.TLabel').pack(side=tk.LEFT, padx=10)
    ttk.Label(status_frame, text="Analysis Complete", foreground='#00E5FF',
             font=('Segoe UI', 9)).pack(side=tk.LEFT)

    # Add some visual polish
    summary_win.configure(bg='#0A0A12')
    for child in container.winfo_children():
        if isinstance(child, ttk.Frame):
            child.configure(style='Card.TFrame')

def show_statistics12():
    global list_of_counts, list_of_classes, total_packet_type_count, classification_count , stats_window_created , current_view ,protocol_colors , type_table_body, class_table_body,classification_colors
    
    # ========== HELPER FUNCTIONS ==========
    def rgb_to_hex(color):
        # Accepts float RGBA or RGB and converts to valid hex
        if isinstance(color, tuple):
            if len(color) == 4:  # RGBA floats
                r, g, b = [int(round(c * 255)) for c in color[:3]]
            elif len(color) == 3 and all(isinstance(c, float) for c in color):  # RGB floats
                r, g, b = [int(round(c * 255)) for c in color]
            elif len(color) == 3:  # already int RGB
                r, g, b = color
            else:
                return '#969696'  # fallback gray
            return '#{:02x}{:02x}{:02x}'.format(r, g, b)
        return '#969696'  # fallback gray

    def get_protocol_colors(protocols):
        cmap = plt.cm.tab20
        return {proto: cmap(i % 20) for i, proto in enumerate(protocols)}
    
    def get_classification_colors(classifications):
        cmap = plt.cm.Paired
        return {cls: cmap(i % 12) for i, cls in enumerate(classifications)}

    def on_checkbox_change(*args):
        update_visualizations()

    def update_visualizations():
        global current_view, chart_display_frame
        
        # Check if chart display frame still exists
        if chart_display_frame is None:
            return
            
        if current_view == "pie":
            update_pie_chart3()
        else:
            print("Updating bar chart")
            update_bar_chart3()

    def update_pie_chart3():
        global chart_display_frame, current_interval, type_vars, protocol_colors, update_scheduled,chart_update_pending
        chart_update_pending = False
        if update_scheduled:
            return
        update_scheduled = True

        def run():
            global update_scheduled
            # Check if chart display frame still exists
            try:
                if chart_display_frame is None or not chart_display_frame.winfo_exists():
                    update_scheduled = False
                    return
                    
                for widget in chart_display_frame.winfo_children():
                    widget.destroy()
            except (tk.TclError, AttributeError):
                update_scheduled = False
                return

            raw_data = total_packet_type_count if current_interval == -1 else list_of_counts[current_interval]
            type_data = {
                k: v for k, v in total_packet_type_count.items()
                if k in type_vars and type_vars[k].get() and isinstance(v, (int, float)) and not math.isnan(v) and v > 0
            }

            total_packets = sum(type_data.values()) or 1
            sorted_types = sorted(type_data.items(), key=lambda x: -x[1])

            if sorted_types:
                fig_pie = plt.Figure(figsize=(8, 7), dpi=100)
                ax_pie = fig_pie.add_subplot(111)
                fig_pie.patch.set_facecolor('#0A0A12')
                ax_pie.set_facecolor('#161622')
                plt.rcParams['text.color'] = '#E0E0FF'
                ax_pie.title.set_color('#00E5FF')

                pie_colors = [protocol_colors[proto] for proto, _ in sorted_types]
                labels = [proto if (count / total_packets) > 0.02 else '' for proto, count in sorted_types]

                wedges, texts, autotexts = ax_pie.pie(
                    [count for _, count in sorted_types],
                    labels=labels,
                    colors=pie_colors,
                    autopct=lambda p: f'{p:.1f}%' if p > 1 else '',
                    startangle=90,
                    textprops={'fontsize': 14, 'color': '#E0E0FF'},
                    pctdistance=0.8,
                    labeldistance=1.05,
                    wedgeprops={'edgecolor': '#303040', 'linewidth': 0.5}
                )

                for text in texts + autotexts:
                    text.set_fontsize(12)

                ax_pie.legend(
                    wedges,
                    [proto for proto, _ in sorted_types],
                    title="Protocols",
                    loc="center left",
                    bbox_to_anchor=(1.1, 0.5),
                    facecolor='#161622',
                    edgecolor='#303040',
                    labelcolor='#E0E0FF',
                    title_fontproperties={'weight': 'bold', 'size': 12}
                )

                ax_pie.set_title("Protocol Distribution", pad=30, fontsize=16)
                ax_pie.axis('equal')

                pie_canvas = FigureCanvasTkAgg(fig_pie, chart_display_frame)
                pie_canvas.draw()
                pie_canvas.get_tk_widget().pack(fill="both", expand=True)
                plt.close(fig_pie)
            else:
                ttk.Label(chart_display_frame, text="No valid protocol data",
                        foreground="#A0A0B0", background='#161622',
                        font=('Segoe UI', 14)).pack(expand=True)

            update_scheduled = False

        # Check if chart_display_frame still exists before calling after
        if chart_display_frame is not None:
            try:
                chart_display_frame.after(100, run)
            except (tk.TclError, AttributeError):
                update_scheduled = False

    def update_bar_chart3():
        global chart_display_frame, current_interval, class_vars, classification_colors, classification_count, list_of_classes, update_scheduled , chart_update_pending
        chart_update_pending = False
        if update_scheduled:
            return
        update_scheduled = True

        def run():
            global update_scheduled
            # Check if chart display frame still exists
            try:
                if chart_display_frame is None or not chart_display_frame.winfo_exists():
                    update_scheduled = False
                    return
                    
                for widget in chart_display_frame.winfo_children():
                    widget.destroy()
            except (tk.TclError, AttributeError):
                update_scheduled = False
                return

            raw_data = classification_count if current_interval == -1 else list_of_classes[current_interval]
            class_data = {
                k: v for k, v in raw_data.items()
                if class_vars[k].get() and isinstance(v, (int, float)) and not math.isnan(v) and v > 0
            }

            if class_data:
                sorted_classes = sorted(class_data.items(), key=lambda x: -x[1])
                fig_bar = plt.Figure(figsize=(8, 6), dpi=80)
                ax_bar = fig_bar.add_subplot(111)

                fig_bar.patch.set_facecolor('#0A0A12')
                ax_bar.set_facecolor('#161622')
                ax_bar.title.set_color('#00E5FF')
                ax_bar.xaxis.label.set_color('#E0E0FF')
                ax_bar.yaxis.label.set_color('#E0E0FF')
                ax_bar.tick_params(axis='x', colors='#E0E0FF')
                ax_bar.tick_params(axis='y', colors='#E0E0FF')
                ax_bar.spines['bottom'].set_color('#303040')
                ax_bar.spines['top'].set_color('#303040')
                ax_bar.spines['right'].set_color('#303040')
                ax_bar.spines['left'].set_color('#303040')

                x_pos = range(len(sorted_classes))
                print("classification_colors333333:", classification_colors)
                bars = ax_bar.bar(
                    x_pos,
                    [count for _, count in sorted_classes],
                    color=[
                        rgb_to_hex(classification_colors.get(cls, (150, 150, 150)))  # fallback to gray
                        for cls, _ in sorted_classes],
                    width=0.6,
                    edgecolor='#303040'
                )

                ax_bar.set_xticks(x_pos)
                ax_bar.set_xticklabels([str(i + 1) for i in x_pos])
                ax_bar.set_title("Classification Counts", pad=20, fontsize=16)
                ax_bar.set_ylabel("Packets", fontsize=14)
                ax_bar.grid(axis='y', linestyle='--', alpha=0.4, color='#303040')

                for bar in bars:
                    height = bar.get_height()
                    ax_bar.text(bar.get_x() + bar.get_width() / 2., height,
                                f'{height:,}',
                                ha='center', va='bottom',
                                fontsize=12, color='#E0E0FF')

                bar_canvas = FigureCanvasTkAgg(fig_bar, chart_display_frame)
                bar_canvas.draw()
                bar_canvas.get_tk_widget().pack(fill="both", expand=True)
                plt.close(fig_bar)
            else:
                ttk.Label(chart_display_frame, text="No valid classification data",
                        foreground="#A0A0B0", background='#161622',
                        font=('Segoe UI', 14)).pack(expand=True)

            update_scheduled = False

        # Check if chart_display_frame still exists before calling after
        if chart_display_frame is not None:
            try:
                chart_display_frame.after(100, run)
            except (tk.TclError, AttributeError):
                update_scheduled = False

    def populate_tables2():
        global current_interval, type_vars, class_vars
        global type_table_body, class_table_body
        global protocol_colors, classification_colors
        global total_packet_type_count, classification_count
        global table_update_pending

        table_update_pending = False  # reset pending flag

        # Check if widgets still exist
        try:
            if type_table_body is None or not type_table_body.winfo_exists():
                return
            if class_table_body is None or not class_table_body.winfo_exists():
                return
        except (tk.TclError, AttributeError):
            return

        initialize_checkboxes()

        type_data = total_packet_type_count if current_interval == -1 else list_of_counts[current_interval]
        class_data = classification_count if current_interval == -1 else list_of_classes[current_interval]

        total_packets = sum(type_data.values()) or 1
        sorted_types = sorted(type_data.items(), key=lambda x: -x[1])

        # Clear existing rows safely
        try:
            if type_table_body and type_table_body.winfo_exists():
                for widget in type_table_body.winfo_children():
                    widget.destroy()
        except (tk.TclError, AttributeError):
            pass
            
        try:
            if class_table_body and class_table_body.winfo_exists():
                for widget in class_table_body.winfo_children():
                    widget.destroy()
        except (tk.TclError, AttributeError):
            pass

        # --- Populate Type Table ---
        for row_idx, (proto, count) in enumerate(sorted_types):
            row_frame = ttk.Frame(type_table_body, style='Card.TFrame')
            row_frame.pack(fill="x", pady=3)

            cb = tk.Checkbutton(
                row_frame,
                variable=type_vars[proto],
                bg='#161622', activebackground='#252538',
                fg='#E0E0FF', activeforeground='#FFFFFF',
                selectcolor='#161622', indicatoron=False,
                width=2, relief='raised', borderwidth=2,
                command=lambda: update_visualizations()
            )
            cb.grid(row=0, column=0, padx=6, pady=3)

            def update_checkbox(var=type_vars[proto], cb=cb):
                cb.config(text="✓" if var.get() else "", foreground="#00E5FF" if var.get() else "#E0E0FF")

            type_vars[proto].trace_add("write", lambda *_, var=type_vars[proto], cb=cb: update_checkbox(var, cb))
            update_checkbox()

            tk.Frame(
                row_frame, width=26, height=26,
                bg=rgb_to_hex(protocol_colors[proto]),
                relief="solid", borderwidth=1
            ).grid(row=0, column=1, padx=6, pady=3)

            ttk.Label(row_frame, text=proto, width=22, anchor="w", style='TLabel', font=('Segoe UI', 11)).grid(row=0, column=2)
            ttk.Label(row_frame, text=f"{count:,}", width=15, anchor="e", style='TLabel', font=('Consolas', 11)).grid(row=0, column=3)
            ttk.Label(row_frame, text=f"{(count / total_packets) * 100:.1f}%", width=12, anchor="e", style='TLabel', font=('Consolas', 11)).grid(row=0, column=4)

        # --- Populate Classification Table ---
        if class_data:
            sorted_classes = sorted(class_data.items(), key=lambda x: -x[1])

            for row_idx, (class_name, count) in enumerate(sorted_classes):
                row_frame = ttk.Frame(class_table_body, style='Card.TFrame')
                row_frame.pack(fill="x", pady=3)

                try:
                    cb = tk.Checkbutton(
                        row_frame,
                        variable=class_vars[class_name],
                        bg='#161622', activebackground='#252538',
                        fg='#E0E0FF', activeforeground='#FFFFFF',
                        selectcolor='#161622', indicatoron=False,
                        width=2, relief='raised', borderwidth=2,
                        command=lambda: update_visualizations()
                    )
                    cb.grid(row=0, column=0, padx=6, pady=3)

                    def update_checkbox(var=class_vars[class_name], cb=cb):
                        cb.config(text="✓" if var.get() else "", foreground="#00E5FF" if var.get() else "#E0E0FF")

                    class_vars[class_name].trace_add("write", lambda *_, var=class_vars[class_name], cb=cb: update_checkbox(var, cb))
                    update_checkbox()
                except Exception as e:
                    print(f"Checkbutton error: {e}")

                try:
                    tk.Frame(
                        row_frame, width=26, height=26,
                        bg=rgb_to_hex(classification_colors.get(class_name, (150, 150, 150))),
                        relief="solid", borderwidth=1
                    ).grid(row=0, column=1, padx=6, pady=3)
                except Exception as e:
                    print(f"Color frame error 1035: {e}")

                ttk.Label(row_frame, text=str(row_idx+1), width=6, anchor="w", style='TLabel', font=('Consolas', 11)).grid(row=0, column=2)
                ttk.Label(row_frame, text=class_name, width=28, anchor="w", style='TLabel', font=('Segoe UI', 11)).grid(row=0, column=3)
                ttk.Label(row_frame, text=f"{count:,}", width=18, anchor="e", style='TLabel', font=('Consolas', 11)).grid(row=0, column=4)

        update_visualizations()

    def schedule_chart_update():
        global chart_update_pending, chart_display_frame
        if not chart_update_pending and chart_display_frame is not None:
            chart_update_pending = True
            try:
                root.after(5000, update_visualizations)
            except (tk.TclError, AttributeError):
                chart_update_pending = False

    def schedule_table_update():
        global table_update_pending, type_table_body, class_table_body
        if not table_update_pending and type_table_body is not None and class_table_body is not None:
            table_update_pending = True
            try:
                root.after(5000, populate_tables2)
            except (tk.TclError, AttributeError):
                table_update_pending = False

    def select_all(state):
            global type_vars, class_vars
            """Select or deselect all checkboxes"""
            for var in (*type_vars.values(), *class_vars.values()):
                var.set(1 if state else 0)
            update_visualizations()
    
    def change_view(view):
        global current_view
        current_view = view
        
        # Update button styles
        pie_btn.configure(style='ViewActive.TButton' if view == "pie" else 'View.TButton')
        bar_btn.configure(style='ViewActive.TButton' if view == "bar" else 'View.TButton')
        
        # Show/hide tables
        if view == "pie":
            protocol_frame.pack(fill="both", expand=True, padx=10, pady=10)
            class_frame.pack_forget()
        else:
            class_frame.pack(fill="both", expand=True, padx=10, pady=10)
            protocol_frame.pack_forget()
        
        update_visualizations()

    def close_stats_window():
        global stats_window_created, chart_display_frame, type_table_body, class_table_body
        global interval_buttons, total_btn, stats_win
        stats_window_created = False
        print("Closing statistics window")
        
        # Clear global references to prevent access to destroyed widgets
        chart_display_frame = None
        type_table_body = None
        class_table_body = None
        interval_buttons = []
        total_btn = None
        
        try:
            if stats_win:
                stats_win.destroy()
        except (tk.TclError, AttributeError):
            pass
        
        stats_win = None

    def set_interval2(idx):
        global current_interval, current_active_interval,interval_buttons,total_btn , prev_current_interval

        try:
            current_interval = idx  # Set currently viewed interval
            print(f"Setting interval to {current_interval}33333333333333333333333333333333")
            for i, btn in enumerate(interval_buttons):
                if i == current_interval == current_active_interval:
                    btn.configure(style='IntervalActivedd.TButton')  # Selected AND active
                elif i == current_active_interval:
                    btn.configure(style='IntervalActived.TButton')   # Active only
                elif i == current_interval:
                    btn.configure(style='IntervalActive.TButton')    # Selected only
                else:
                    btn.configure(style='Interval.TButton')          # Default

            if current_interval == -1:  # TOTAL button clicked
                total_btn.configure(style='IntervalActive.TButton')
                for i, btn in enumerate(interval_buttons):
                    # Restore correct style when switching to TOTAL
                    if i == current_active_interval:
                        btn.configure(style='IntervalActived.TButton')
                    else:
                        btn.configure(style='Interval.TButton')
            else:
                total_btn.configure(style='Interval.TButton')

            populate_tables2()

        except Exception as e:
            print(f"[set_interval2] Error: {e}")

    def set_interval3(idx):
        global current_interval, current_active_interval,interval_buttons,total_btn , prev_current_interval

        try:
            current_interval = idx  # Set currently viewed interval
            print(f"Setting interval to {current_interval}4444444444444444444444")
            prev_current_interval = current_active_interval
            for i, btn in enumerate(interval_buttons):
                if i == current_interval == current_active_interval:
                    btn.configure(style='IntervalActivedd.TButton')  # Selected AND active
                elif i == current_active_interval:
                    btn.configure(style='IntervalActived.TButton')   # Active only
                elif i == current_interval:
                    btn.configure(style='IntervalActive.TButton')    # Selected only
                else:
                    btn.configure(style='Interval.TButton')          # Default

            if current_interval == -1:  # TOTAL button clicked
                total_btn.configure(style='IntervalActive.TButton')
                for i, btn in enumerate(interval_buttons):
                    # Restore correct style when switching to TOTAL
                    if i == current_active_interval:
                        btn.configure(style='IntervalActived.TButton')
                    else:
                        btn.configure(style='Interval.TButton')
            else:
                total_btn.configure(style='Interval.TButton')

            if current_active_interval == current_interval:
                populate_tables2()

        except Exception as e:
            print(f"[set_interval3] Error: {e}")

    def initialize_checkboxes():
            global type_vars, class_vars, total_packet_type_count, classification_count
            
            type_vars.clear()
            class_vars.clear()
            
            for proto in total_packet_type_count.keys():
                type_vars[proto] = tk.IntVar(value=1)
                type_vars[proto].trace_add("write", on_checkbox_change)
            
            for cls in classification_count.keys():
                class_vars[cls] = tk.IntVar(value=1)
                class_vars[cls].trace_add("write", on_checkbox_change)

    def create_interval_button(idx):
            btn = ttk.Button(
                btn_frame,
                text=f"Interval {idx+1}",
                width=14,
                command=lambda: set_interval2(idx),
                style='IntervalActive.TButton' if idx == 0 else 'Interval.TButton'
            )
            return btn

    # ========== WINDOW SETUP ==========
    if stats_window_created is False:
        global stats_win, chart_display_frame, type_table_body, class_table_body
        global interval_buttons, total_btn
        stats_window_created = True
        stats_win = tk.Toplevel(root)
        stats_win.title("Interactive Packet Statistics")
        stats_win.geometry("1500x950")
        stats_win.minsize(1200, 800)
        
        # Configure dark theme
        style = ttk.Style()
        style.theme_use('clam')
        
        # Custom styles
        style.configure('TFrame', background='#0A0A12')
        style.configure('Card.TFrame', background='#161622', relief='raised', borderwidth=1)
        style.configure('TLabel', background='#0A0A12', foreground='#E0E0FF', font=('Segoe UI', 11))
        style.configure('Header.TLabel', font=('Segoe UI Semibold', 13), foreground='#00E5FF')
        style.configure('View.TButton', background='#252538', foreground='#E0E0FF',
                    font=('Segoe UI Semibold', 11), borderwidth=1)
        style.configure('ViewActive.TButton', background='#00E5FF', foreground='#0A0A12',
                    font=('Segoe UI Bold', 11))
        
        # Custom checkbox style with X mark

        global style_created
        try:
            if not style_created:
                style.element_create('Custom.Checkbutton.indicator', 'from', 'clam')
                style_created = True
            # now apply styles or create window
        except Exception as e:
            print(f"Style error: {e}")
        style.layout('Custom.TCheckbutton', [
            ('Checkbutton.padding', {'sticky': 'nswe', 'children': [
                ('Checkbutton.indicator', {'side': 'left', 'sticky': ''}),
                ('Checkbutton.focus', {'side': 'left', 'sticky': '', 'children': [
                    ('Checkbutton.label', {'sticky': 'nswe'})
                ]})
            ]})
        ])
        style.configure('Custom.TCheckbutton',
                    background='#161622',
                    foreground='#E0E0FF',
                    indicatorbackground='#161622',
                    indicatordiameter=20,
                    indicatorrelief='raised',
                    padding=8,
                    borderwidth=2)
        style.map('Custom.TCheckbutton',
                background=[('active', '#252538')],
                foreground=[('active', '#FFFFFF')],
                indicatorcolor=[('selected', '#00E5FF')],
                indicatorrelief=[('selected', 'sunken'),
                                ('!selected', 'raised')])
        
        # Style for interval buttons
        style.configure('Interval.TButton', 
                    background='#252538', 
                    foreground='#E0E0FF',
                    font=('Segoe UI Semibold', 11),
                    borderwidth=1)
        style.configure('IntervalActive.TButton', 
                    background='#00E5FF', 
                    foreground='#0A0A12',
                    font=('Segoe UI Bold', 11))
        style.configure("IntervalActived.TButton", background="#EB0B0B", foreground="white", padding=6)
        style.configure("IntervalActivedd.TButton", background="#10D809", foreground="white", padding=6)
        # Store references to all interval buttons
        global interval_buttons
        interval_buttons = []

        # Main container
        main_frame = ttk.Frame(stats_win, style='TFrame')
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Header frame
        header_frame = ttk.Frame(main_frame, style='Card.TFrame')
        header_frame.pack(fill="x", pady=(0, 20))
        
        ttk.Label(header_frame, text="PACKET STATISTICS ANALYZER", 
                font=('Segoe UI Semibold', 16), style='Header.TLabel').pack(side="left", padx=20, pady=10)
        
        ttk.Button(header_frame, text="✕ Close", command=close_stats_window, 
                style='ViewActive.TButton').pack(side="right", padx=15, pady=8)

        # Control frame with view toggle buttons
        control_frame = ttk.Frame(main_frame, style='Card.TFrame')
        control_frame.pack(fill="x", pady=(0, 20))
        
        # View toggle buttons
        view_frame = ttk.Frame(control_frame, style='Card.TFrame')
        view_frame.pack(side="left", padx=15)
        
        pie_btn = ttk.Button(view_frame, text="Protocol View", 
                            command=lambda: change_view("pie"),
                            style='ViewActive.TButton')
        pie_btn.pack(side="left", padx=5)
        
        bar_btn = ttk.Button(view_frame, text="Classification View", 
                            command=lambda: change_view("bar"),
                            style='View.TButton')
        bar_btn.pack(side="left", padx=5)
        
        # Selection buttons
        select_frame = ttk.Frame(control_frame, style='Card.TFrame')
        select_frame.pack(side="right", padx=15)
        
        ttk.Button(select_frame, text="Select All", 
                command=lambda: select_all(True)).pack(side="left", padx=5)
        ttk.Button(select_frame, text="Clear All", 
                command=lambda: select_all(False)).pack(side="left", padx=5)
        
        
        
        # Interval buttons
        btn_container = ttk.Frame(main_frame, style='Card.TFrame')
        btn_container.pack(fill="x", pady=(0, 20))
        
        canvas = tk.Canvas(btn_container, height=55, highlightthickness=0, bg='#161622')
        scroll_x = ttk.Scrollbar(btn_container, orient="horizontal", command=canvas.xview)
        
        btn_frame = ttk.Frame(canvas, style='Card.TFrame')
        btn_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        
        canvas.create_window((0,0), window=btn_frame, anchor="nw")
        canvas.configure(xscrollcommand=scroll_x.set)
        
        canvas.pack(side="top", fill="x", expand=True)
        scroll_x.pack(side="bottom", fill="x")
        
        # Add interval buttons
        for i in range(len(list_of_counts)):
            btn = create_interval_button(i)
            btn.pack(side="left", padx=6, pady=4)
            interval_buttons.append(btn)
        global total_btn
        # Add "Total" button
        total_btn = ttk.Button(
            btn_frame,
            text="TOTAL",
            width=12,
            style='Interval.TButton',
            command=lambda: set_interval2(-1)
        )
        total_btn.pack(side="left", padx=12, pady=4)
        
        # Main content area - 50/50 split
        content_frame = ttk.Frame(main_frame, style='TFrame')
        content_frame.pack(fill="both", expand=True)
        
        # Left panel (Tables) - 50% width
        tables_panel = ttk.Frame(content_frame, style='Card.TFrame')
        tables_panel.pack(side="left", fill="both", expand=True, padx=(0, 10))
        
        # Protocol table frame
        protocol_frame = ttk.Frame(tables_panel, style='Card.TFrame')
        
        ttk.Label(protocol_frame, text="PROTOCOL STATISTICS", style='Header.TLabel').pack(anchor='w', padx=15, pady=(10, 8))
        
        # Protocol Table Header
        type_table_header = ttk.Frame(protocol_frame, style='Card.TFrame')
        type_table_header.pack(fill="x", pady=(0, 10))
        
        ttk.Label(type_table_header, text="", width=3, style='TLabel').grid(row=0, column=0)
        ttk.Label(type_table_header, text="", width=3, style='TLabel').grid(row=0, column=1)
        ttk.Label(type_table_header, text="Protocol", width=22, anchor="w", 
                style='Header.TLabel').grid(row=0, column=2)
        ttk.Label(type_table_header, text="Count", width=15, anchor="e", 
                style='Header.TLabel').grid(row=0, column=3)
        ttk.Label(type_table_header, text="%", width=12, anchor="e", 
                style='Header.TLabel').grid(row=0, column=4)
        
        type_table_body = ttk.Frame(protocol_frame, style='Card.TFrame')
        type_table_body.pack(fill="x")
        
        # Classification table frame (initially hidden)
        class_frame = ttk.Frame(tables_panel, style='Card.TFrame')
        
        ttk.Label(class_frame, text="CLASSIFICATION STATISTICS", style='Header.TLabel').pack(anchor='w', padx=15, pady=(10, 8))
        
        # Classification Table Header
        class_table_header = ttk.Frame(class_frame, style='Card.TFrame')
        class_table_header.pack(fill="x", pady=(0, 10))
        
        ttk.Label(class_table_header, text="", width=3, style='TLabel').grid(row=0, column=0)
        ttk.Label(class_table_header, text="", width=3, style='TLabel').grid(row=0, column=1)
        ttk.Label(class_table_header, text="#", width=6, anchor="w", 
                style='Header.TLabel').grid(row=0, column=2)
        ttk.Label(class_table_header, text="Classification", width=28, anchor="w", 
                style='Header.TLabel').grid(row=0, column=3)
        ttk.Label(class_table_header, text="Count", width=18, anchor="e", 
                style='Header.TLabel').grid(row=0, column=4)
        
        class_table_body = ttk.Frame(class_frame, style='Card.TFrame')
        class_table_body.pack(fill="x")
        
        # Right panel (Chart display) - 50% width
        chart_panel = ttk.Frame(content_frame, style='Card.TFrame')
        chart_panel.pack(side="right", fill="both", expand=True, padx=(10, 0))
        
        # Frame for chart display
        global chart_display_frame , current_view, protocol_colors, classification_colors
        chart_display_frame = ttk.Frame(chart_panel, style='Card.TFrame')
        chart_display_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Initialize variables
        protocol_colors = get_protocol_colors(total_packet_type_count.keys())
        classification_colors = get_classification_colors(classification_count.keys())

        # Initial display
        protocol_frame.pack(fill="both", expand=True, padx=10, pady=10)
        set_interval3(0)
        change_view("pie")  # Initialize with pie chart view
        
        # Configure window background
        stats_win.configure(bg='#0A0A12')
        for child in main_frame.winfo_children():
            if isinstance(child, ttk.Frame):
                child.configure(style='Card.TFrame')
    else:
        print("Stats window already created, reusing the existing one.")
        print(f"Current active interval: {current_active_interval}, Current interval: {current_interval}")
        try:
            set_interval3(current_interval)
        except Exception as e:
            print(f"Error setting interval: {e}")
        if current_active_interval == current_interval:
            schedule_chart_update()
            schedule_table_update()

def filter_tokens(tokens):
    return [t for t in tokens if t.strip(string.punctuation) != '']

def process_packet_data(packet) -> list:
    clean_str = remove_ansi_escape_sequences(str(packet))
    tokens = tokenizer.tokenize(clean_str)
    return filter_tokens(tokens)

def rule_based_classification(summary: str) -> str:
    
    # Normalize the summary for case-insensitive matching
    normalized_summary = summary.upper()
    
    # ----- Application Layer Protocols -----
    # Email Protocols
    if any(x in normalized_summary for x in ["PORT 25", "SMTP"]):
        return "Email (SMTP - Simple Mail Transfer Protocol)"
    if any(x in normalized_summary for x in ["PORT 110", "POP3"]):
        return "Email (POP3 - Post Office Protocol v3)"
    if any(x in normalized_summary for x in ["PORT 143", "IMAP"]):
        return "Email (IMAP - Internet Message Access Protocol)"
    if any(x in normalized_summary for x in ["PORT 465", "SMTPS"]):
        return "Email (SMTPS - SMTP Secure)"
    if any(x in normalized_summary for x in ["PORT 587", "SUBMISSION"]):
        return "Email (Message Submission)"
    if any(x in normalized_summary for x in ["PORT 993", "IMAPS"]):
        return "Email (IMAPS - IMAP Secure)"
    if any(x in normalized_summary for x in ["PORT 995", "POP3S"]):
        return "Email (POP3S - POP3 Secure)"

    # Web Protocols
    if any(x in normalized_summary for x in ["PORT 80", "HTTP"]):
        return "Web Traffic (HTTP - Hypertext Transfer Protocol)"
    if any(x in normalized_summary for x in ["PORT 443", "HTTPS", "TLS", "SSL"]):
        return "Web Traffic (HTTPS - HTTP Secure)"
    if any(x in normalized_summary for x in ["PORT 8080", "HTTP-ALT"]):
        return "Web Traffic (HTTP Alternate)"
    if any(x in normalized_summary for x in ["PORT 8443", "HTTPS-ALT"]):
        return "Web Traffic (HTTPS Alternate)"

    # File Transfer
    if any(x in normalized_summary for x in ["PORT 21", "FTP"]):
        return "File Transfer (FTP - File Transfer Protocol)"
    if any(x in normalized_summary for x in ["PORT 22", "SFTP", "SSH"]):
        return "Secure File Transfer (SFTP/SSH)"
    if any(x in normalized_summary for x in ["PORT 69", "TFTP"]):
        return "File Transfer (TFTP - Trivial FTP)"

    # Remote Access
    if any(x in normalized_summary for x in ["PORT 22", "SSH"]):
        return "Secure Shell (SSH - Secure Shell)"
    if any(x in normalized_summary for x in ["PORT 23", "TELNET"]):
        return "Remote Access (Telnet)"
    if any(x in normalized_summary for x in ["PORT 3389", "RDP"]):
        return "Remote Desktop (RDP)"

    # Database Protocols
    if any(x in normalized_summary for x in ["PORT 1433", "MSSQL"]):
        return "Database (Microsoft SQL Server)"
    if any(x in normalized_summary for x in ["PORT 1521", "ORACLE"]):
        return "Database (Oracle)"
    if any(x in normalized_summary for x in ["PORT 3306", "MYSQL"]):
        return "Database (MySQL)"
    if any(x in normalized_summary for x in ["PORT 5432", "POSTGRES"]):
        return "Database (PostgreSQL)"

    # Network Services
    if any(x in normalized_summary for x in ["PORT 53", "DNS"]):
        return "DNS (Domain Name System)"
    if any(x in normalized_summary for x in ["PORT 67", "DHCP"]):
        return "DHCP (Dynamic Host Configuration)"
    if any(x in normalized_summary for x in ["PORT 161", "SNMP"]):
        return "Network Management (SNMP - Simple Network Management Protocol)"
    if any(x in normalized_summary for x in ["PORT 389", "LDAP"]):
        return "Directory Services (LDAP)"
    if any(x in normalized_summary for x in ["PORT 636", "LDAPS"]):
        return "Directory Services (LDAP Secure)"

    # VoIP and Media
    if any(x in normalized_summary for x in ["PORT 5060", "SIP"]):
        return "VoIP Signaling (SIP - Session Initiation Protocol)"
    if any(x in normalized_summary for x in ["PORT 5061", "SIPS"]):
        return "VoIP Signaling (SIP Secure)"
    if any(x in normalized_summary for x in ["PORT 1935", "RTMP"]):
        return "Media Streaming (RTMP)"
    if any(x in normalized_summary for x in ["PORT 554", "RTSP"]):
        return "Media Streaming (RTSP)"

    # ----- Transport Layer Protocols -----
    if "TCP" in normalized_summary:
        # Try to classify TCP traffic that wasn't caught by application rules
        if "PROTOCOL: 6" in normalized_summary:  # TCP protocol number
            return "General TCP Traffic"
    
    if "UDP" in normalized_summary:
        # Try to classify UDP traffic that wasn't caught by application rules
        if "PROTOCOL: 17" in normalized_summary:  # UDP protocol number
            return "General UDP Traffic"
    
    # ----- Network Layer Protocols -----
    if "ARP" in normalized_summary:
        return "Address Resolution (ARP)"
    if "ICMP" in normalized_summary:
        if "TYPE:8" in normalized_summary or "ECHO REQUEST" in normalized_summary:
            return "Network Diagnostics (ICMP Echo Request)"
        if "TYPE:0" in normalized_summary or "ECHO REPLY" in normalized_summary:
            return "Network Diagnostics (ICMP Echo Reply)"
        if "TYPE:3" in normalized_summary:
            return "Network Diagnostics (ICMP Destination Unreachable)"
        if "TYPE:11" in normalized_summary:
            return "Network Diagnostics (ICMP Time Exceeded)"
        return "Network Diagnostics (ICMP)"
    
    if "IPv6" in normalized_summary:
        return "IPv6 Traffic"
    
    # ----- Special Cases -----
    if "MALWARE" in normalized_summary or "EXPLOIT" in normalized_summary:
        return "Security Threat (Malware/Exploit)"
    if "SCAN" in normalized_summary or "PROBE" in normalized_summary:
        return "Security Event (Scan/Probe)"
    
    # ----- Default Cases -----
    if "IPv4" in normalized_summary:
        return "General IPv4 Traffic"
    
    return "Uncategorized Network Traffic"

def ml_based_classification(summary: str) -> str:
    global vectorizer, clf, ml_enabled
    if not vectorizer or not clf:
        print("ML model not loaded")
        return "Uncategorized"
    try:
        vec = vectorizer.transform([summary])
        prediction = clf.predict(vec)[0]
        if prediction is None:
            print(f"ML returned None for summary: {summary}")
            return "Uncategorized"
        return str(prediction)
    except Exception as e:
        print(f"ML error for summary '{summary}': {e}")
        return "Uncategorized"

def classify_summary(summary: str) -> str:
    label = rule_based_classification(summary)
    if label == "Uncategorized Network Traffic" and ml_enabled:
        #print("Using ML classification for uncategorized traffic")
        try:
            label = ml_based_classification(summary)
            #print(f"ML classification result: {label}")
        except Exception as e:
            print(f"ML classification failed for summary: {summary}, Error: {e}")
            label = "Unknown"
    return label

def generate_readable_summary(pkt):
    summary_parts = []
    if hasattr(pkt, 'eth'):
        eth_type = getattr(pkt.eth, 'type', None)
        if eth_type:
            summary_parts.append(f"Type: Ethernet ({eth_type})")

    if hasattr(pkt, 'ip'):
        summary_parts.append("Type: IPv4")
        protocol = getattr(pkt.ip, 'proto', None)
        if protocol:
            summary_parts.append(f"Protocol: {protocol}")
    elif hasattr(pkt, 'ipv6'):
        summary_parts.append("Type: IPv6")
        if hasattr(pkt, 'icmpv6'):
            summary_parts.append("Protocol: ICMPv6")
            opcode = getattr(pkt.icmpv6, 'type', None)
            if opcode:
                summary_parts.append(f"Opcode: {opcode}")
    elif hasattr(pkt, 'arp'):
        summary_parts.append("Type: ARP")
        opcode = getattr(pkt.arp, 'opcode', None)
        if opcode:
            summary_parts.append(f"Opcode: {opcode}")

    src = dst = None
    if hasattr(pkt, 'eth'):
        src = getattr(pkt.eth, 'src', None)
        dst = getattr(pkt.eth, 'dst', None)
    if hasattr(pkt, 'ip'):
        src = getattr(pkt.ip, 'src', src)
        dst = getattr(pkt.ip, 'dst', dst)
    if hasattr(pkt, 'ipv6'):
        src = getattr(pkt.ipv6, 'src', src)
        dst = getattr(pkt.ipv6, 'dst', dst)
    if hasattr(pkt, 'tcp'):
        src_port = getattr(pkt.tcp, 'srcport', None)
        dst_port = getattr(pkt.tcp, 'dstport', None)
        if src_port:
            summary_parts.append(f"Port {src_port}")
        if dst_port:
            summary_parts.append(f"Port {dst_port}")

    if hasattr(pkt, 'udp'):
        src_port = getattr(pkt.udp, 'srcport', None)
        dst_port = getattr(pkt.udp, 'dstport', None)
        if src_port:
            summary_parts.append(f"Port {src_port}")
        if dst_port:
            summary_parts.append(f"Port {dst_port}")

    # Also include protocol names for clarity:
    if hasattr(pkt, 'http'):
        summary_parts.append("HTTP")
    if hasattr(pkt, 'dns'):
        summary_parts.append("DNS")
    if hasattr(pkt, 'ssl') or hasattr(pkt, 'tls'):
        summary_parts.append("HTTPS")
    if hasattr(pkt, 'icmp'):
        summary_parts.append("ICMP")

    if src:
        summary_parts.append(f"Source: {src}")
    if dst:
        summary_parts.append(f"Destination: {dst}")

    if hasattr(pkt, 'arp'):
        sender_mac = getattr(pkt.arp, 'src_hw_mac', None)
        target_mac = getattr(pkt.arp, 'dst_hw_mac', None)
        if sender_mac:
            summary_parts.append(f"Sender MAC: {sender_mac}")
        if target_mac:
            summary_parts.append(f"Target MAC: {target_mac}")

    return " ".join(summary_parts)

def detect_intrusion_signature_based(pkt) -> list:
    alerts = []
    src_ip = getattr(pkt.ip, 'src', None) if hasattr(pkt, 'ip') else None
    dst_ip = getattr(pkt.ip, 'dst', None) if hasattr(pkt, 'ip') else None
    if src_ip and dst_ip and src_ip == dst_ip:
        alerts.append("\u26a0\ufe0f Spoofed IP address (src == dst)")

    if hasattr(pkt, 'arp'):
        sender_mac = getattr(pkt.arp, 'src_hw_mac', '')
        target_mac = getattr(pkt.arp, 'dst_hw_mac', '')
        if sender_mac == target_mac:
            alerts.append("\u26a0\ufe0f Possible ARP spoofing (MAC src == dst)")

    if hasattr(pkt, 'icmp'):
        alerts.append("\u26a0\ufe0f ICMP traffic detected")

    return alerts

def format_summary(summary: str ,classifi, ii) -> str:
        global current_active_interval
        current_active_interval = ii
        total = sum(summary.values())
        lines = [f"--- Summary of Captured Packets {ii + 1}---",
                f"Total Packets Captured: {total}\n",
                "By Type:"]
        for k, v in summary.items():
            lines.append(f"- {k}: {v}")

        lines.append("\nBy Classification1:")
        for k, v in classifi.items():
            lines.append(f"- {k}: {v}")

        return "\n".join(lines)

def total_format_summary():
        total = sum(total_packet_type_count.values())
        lines = [f"--- Summary of Captured Packets ---",
                f"Total Packets Captured: {total}\n",
                "By Type:"]
        for k, v in total_packet_type_count.items():
            lines.append(f"- {k}: {v}")

        lines.append("\nBy Classification1:")
        for k, v in classification_count.items():
            lines.append(f"- {k}: {v}")

        lines.append("\nAlerts Detected:")
        if any(v > 0 for v in alert_count.values()):
            for k, v in alert_count.items():
                if v > 0:
                    lines.append(f"- {k}: {v}")
        else:
            lines.append("- None")

        return "\n".join(lines)

def list_interfaces():
    try:
        result = subprocess.run(
            [pyshark.tshark.tshark_path, "-D"],
            capture_output=True,
            text=True,
            check=True
        )
        lines = result.stdout.strip().split("\n")
        interfaces = []
        for line in lines:
            match = re.match(r"(\d+)\.\s+(.+)", line)
            if match:
                num, desc = match.groups()
                interfaces.append(f"{num}. {desc}")
        return interfaces
    except subprocess.CalledProcessError as e:
        messagebox.showerror("Error", f"Failed to list interfaces:\n{e.stderr}")
        return []

# === Packet Processing and Capture ===

def packet_handler(pkt, current_count):
    try:
        summary = generate_readable_summary(pkt)
        label = classify_summary(summary)
        alerts = detect_intrusion_signature_based(pkt)
        alert_msg = " | ".join(alerts) if alerts else ""
        full_label = label
        if alert_msg:
            full_label += f" [{alert_msg}]"

        # Update stats by more detailed types - with bounds checking
        if hasattr(pkt, 'ip'):
            total_packet_type_count["IPv4"] += 1
            if "IPv4" in current_count:
                current_count["IPv4"] += 1
        if hasattr(pkt, 'ipv6'):
            total_packet_type_count["IPv6"] += 1
            if "IPv6" in current_count:
                current_count["IPv6"] += 1
        if hasattr(pkt, 'arp'):
            total_packet_type_count["ARP"] += 1
            if "ARP" in current_count:
                current_count["ARP"] += 1
        if hasattr(pkt, 'tcp'):
            total_packet_type_count["TCP"] += 1
            if "TCP" in current_count:
                current_count["TCP"] += 1
            if hasattr(pkt, 'http'):
                total_packet_type_count["HTTP"] += 1
                if "HTTP" in current_count:
                    current_count["HTTP"] += 1
            elif hasattr(pkt, 'ssl') or hasattr(pkt, 'tls'):
                total_packet_type_count["HTTPS"] += 1
                if "HTTPS" in current_count:
                    current_count["HTTPS"] += 1
        elif hasattr(pkt, 'udp'):
            total_packet_type_count["UDP"] += 1
            if "UDP" in current_count:
                current_count["UDP"] += 1
            if hasattr(pkt, 'dns'):
                total_packet_type_count["DNS"] += 1
                if "DNS" in current_count:
                    current_count["DNS"] += 1
        elif hasattr(pkt, 'icmp'):
            total_packet_type_count["ICMP"] += 1
            if "ICMP" in current_count:
                current_count["ICMP"] += 1

        # Update classification counts safely
        if 0 <= ii < len(list_of_classes):
            classification_count[label] = classification_count.get(label, 0) + 1
            list_of_classes[ii][label] = list_of_classes[ii].get(label, 0) + 1

        # Update alert counts
        if "Spoofed IP address" in alert_msg:
            alert_count["Spoofed IP Address"] += 1
        if "ARP spoofing" in alert_msg:
            alert_count["ARP Spoofing"] += 1
        if "ICMP flood" in alert_msg or "ICMP traffic detected" in alert_msg:
            alert_count["ICMP Flood"] += 1

        # Queue for GUI update
        packet_queue.put((summary, full_label))
        return summary
    except Exception as e:
        print(f"Error in packet_handler: {e}")
        packet_queue.put((f"[Error]: {e}", "Error"))
        return None

def stop_capture():
    """Pause the capture (can be resumed)"""
    global capture_running
    capture_stop_event.set()
    status_var.set("Capture paused by user.")
    print("Capture paused - event set but thread continues")

def terminate_capture():
    """Completely stop the capture (cannot be resumed)"""
    global capture_running, capture_thread
    capture_stop_event.set()
    capture_running = False
    status_var.set("Capture terminated by user.")
    print("Capture terminated - stopping completely")
    
    # Wait for thread to finish
    if capture_thread and capture_thread.is_alive():
        capture_thread.join(timeout=2.0)
    capture_thread = None

def resume_capture():
    global capture_running, capture_thread
    # Check if capture is paused (stop event is set)
    if capture_stop_event.is_set() and capture_running:  
        capture_stop_event.clear()  
        status_var.set("Capture resumed.")
        print("Capture resumed - event cleared")
        
        # Ensure GUI updates continue
        update_gui_from_queue()
    elif not capture_running:
        # If capture was completely stopped, restart it
        capture_stop_event.clear()  
        capture_running = True
        status_var.set("Capture restarted.")
        print("Capture restarted - starting new thread")
        
        # Check if we need to restart the capture thread
        if not hasattr(globals(), 'capture_thread') or capture_thread is None or not capture_thread.is_alive():
            print("Starting new capture thread...")
            try:
                # Restart the capture in a new thread
                capture_thread = threading.Thread(target=threaded_capture_live, daemon=True)
                capture_thread.start()
                print("New capture thread started")
            except Exception as e:
                print(f"Error starting capture thread: {e}")
                capture_running = False
                status_var.set(f"Error starting capture: {e}")
        
        # Ensure GUI updates continue
        update_gui_from_queue()
    else:
        status_var.set("Capture is already running.")

def capture_packets_live(iface, total_duration, interval_duration):
    global start_time, end_time, current_time, ii, capture_running
    start_time = datetime.datetime.now()
    end_time = start_time + datetime.timedelta(seconds=total_duration)
    current_time = start_time
    ren = total_duration // interval_duration
    global list_of_counts 
    global list_of_classes
    ii = 0  # Reset interval counter
    list_of_counts = [total_packet_type_count.copy() for _ in range(ren)]
    print(f"Total Duration: {total_duration}, Interval duration: {interval_duration} seconds")
    print(f"Total intervals: {ren}")
    
    # Reset counters
    for key in total_packet_type_count:
        total_packet_type_count[key] = 0
    classification_count.clear()
    list_of_classes = [{} for _ in range(ren)]
    for key in alert_count:
        alert_count[key] = 0
    
    try:
        while current_time < end_time and ii < ren:
            # Check if capture is stopped - wait for resume
            while capture_stop_event.is_set():
                print("Capture paused, waiting for resume...")
                time.sleep(0.5)  # Small delay to prevent busy waiting
                if not capture_running:  # Check if we should exit completely
                    break
            
            # If we broke out of the pause loop due to not running, exit
            if not capture_running:
                break
                
            interval_start_time = time.time()
            print(f"Starting interval {ii + 1}/{ren}")
            
            # Initialize interval counters
            for key in list_of_counts[ii]:
                list_of_counts[ii][key] = 0
            
            # Create capture for this interval
            capture = pyshark.LiveCapture(interface=iface)
            
            try:
                for pkt in capture.sniff_continuously():
                    # Check for stop during packet processing
                    if capture_stop_event.is_set():
                        print("Capture paused during packet processing")
                        break
                    
                    # Process packet
                    packet_handler(pkt, list_of_counts[ii])
                    
                    # Check if interval time has elapsed
                    if time.time() - interval_start_time >= interval_duration:
                        print(f"Interval {ii + 1} time elapsed")
                        break
                        
            except Exception as e:
                print(f"Error during packet capture: {e}")
            finally:
                try:
                    capture.close()
                except:
                    pass

            # Only advance to next interval if we completed this one (not paused)
            if not capture_stop_event.is_set():
                # Update time and index after interval ends
                current_time += datetime.timedelta(seconds=interval_duration)
                print(f"Interval {ii + 1} complete. Packets: {sum(list_of_counts[ii].values())}")
                print(f"Classifications: {list_of_classes[ii]}")
                ii += 1
                
                if ii >= ren:
                    print("All intervals completed.")
                    break
                
    except Exception as e:
        print(f"Error in capture_packets_live: {e}")
    finally:
        capture_running = False
        print("Capture session ended")
               
def update_progress_status(start, end):
    current = datetime.datetime.now()
    if end <= start:
        percent = 100
    else:
        percent = ((current - start) / (end - start)) * 100
        percent = max(0, min(percent, 100))  # Clamp to [0, 100]
    
    progress_var.set(percent)
    progress_label.config(text=f"Progress: {percent:.1f}%")
    elapsed_sec = (current - start).total_seconds()
    total_sec = (end - start).total_seconds()
    status_var.set(f"Time progress: {elapsed_sec:.1f} sec elapsed of {total_sec:.1f} sec")

def update_gui_from_queue():
    global ii, list_of_classes, start_time, end_time, current_time, stats_window_created, ctt, list_of_packets
    updated = False
    
    try:
        while not packet_queue.empty():
            summary, label = packet_queue.get()
            output_box.config(state='normal')
            
            if "⚠️" in label or "Warning" in label or "alert" in label.lower():
                output_box.insert(tk.END, f"{summary}\n→ Classified as: {label}\n\n", 'alert')
                list_of_packets.append((summary, label))
            else:
                output_box.insert(tk.END, f"{summary}\n→ Classified as: {label}\n\n")
                list_of_packets.append((summary, label))
            output_box.see(tk.END)
            output_box.config(state='disabled')
            updated = True
    except Exception as e:
        print(f"Error processing packet queue: {e}")
    
    # Only update summary if we have valid data
    if updated and start_time and end_time:
        try:
            update_progress_status(start_time, end_time)
            
            # Current interval summary in summary_box - check bounds
            if 0 <= ii < len(list_of_classes) and 0 <= ii < len(list_of_counts):
                current_summary = format_summary(list_of_counts[ii], list_of_classes[ii], ii)
                list_of_summaries.append(current_summary)
                summary_box.config(state='normal')
                summary_box.delete("1.0", tk.END)
                summary_box.insert(tk.END, f"--- Current Interval Summary {ii + 1} of {len(list_of_classes)}---\n{current_summary}")
                summary_box.config(state='disabled')
        except Exception as e:
            print(f"Error updating summary: {e}")

    # Continue GUI updates even when paused (but not when completely stopped)
    # Check if capture thread is still alive or if we're just paused
    global capture_thread
    should_continue_updates = (
        capture_running or 
        (capture_thread and capture_thread.is_alive()) or
        capture_stop_event.is_set()  # Continue updates even when paused
    )
    
    if should_continue_updates:
        if stats_window_created:
            ctt += 1
        if stats_window_created and ctt >= 15:
            try:
                show_statistics12()
            except Exception as e:
                print(f"Error in show_statistics12: {e}")
            ctt = 0 
        root.after(50, update_gui_from_queue)

def threaded_capture_live():
    global capture_running ,duration 
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        iface_full = iface_var.get()
        match = re.match(r"\d+\.\s+(\\Device\\NPF_[^ ]+)", iface_full)
        iface = match.group(1) if match else iface_full

        duration = int(total_time_entry.get())*60
        interval = int(segment_duration_entry.get())
        if not iface:
            messagebox.showerror("Input Error", "Please select a network interface.")
            return

        status_var.set("Capturing live...")

        # Run capture synchronously but in this thread to avoid blocking GUI
        capture_packets_live(iface, duration , interval )
        capture_running = False
        status_var.set("Capture complete.")
    except ValueError:
        messagebox.showerror("Input Error", "Duration must be an integer.")
        status_var.set("Input error.")
    except Exception as e:
        messagebox.showerror("Error", str(e))
        status_var.set("Error during capture.")

def save_summary3():
    base_folder = "saved_summaries"
    os.makedirs(base_folder, exist_ok=True)

    def rgb_to_hex(color):
        # Accepts float RGBA or RGB and converts to valid hex
        if isinstance(color, tuple):
            if len(color) == 4:  # RGBA floats
                r, g, b = [int(round(c * 255)) for c in color[:3]]
            elif len(color) == 3 and all(isinstance(c, float) for c in color):  # RGB floats
                r, g, b = [int(round(c * 255)) for c in color]
            elif len(color) == 3:  # already int RGB
                r, g, b = color
            else:
                return '#969696'  # fallback gray
            return '#{:02x}{:02x}{:02x}'.format(r, g, b)
        return '#969696'  # fallback gray


    try:
        # Save text summary
        with open(os.path.join(base_folder, "capture_summary.txt"), 'w') as f:
            for i, summary in enumerate(list_of_summaries):
                f.write(f"--- Summary of Captured Packets {i + 1} ---\n")
                f.write(summary + "\n\n")
            f.write(total_format_summary())

        # Save charts and tables per interval
        for i, (class_data, type_data) in enumerate(zip(list_of_classes, list_of_counts)):
            interval_label = f"interval_{i + 1}"

            # Prepare filtered data
            filtered_class_data = {
                k: v for k, v in class_data.items()
                if isinstance(v, (int, float)) and not math.isnan(v) and v > 0
            }
            filtered_type_data = {
                k: v for k, v in type_data.items()
                if isinstance(v, (int, float)) and not math.isnan(v) and v > 0
            }

            if not filtered_class_data:
                continue  # Skip empty intervals

            # --- Save Bar Chart ---
            fig_bar = plt.Figure(figsize=(8, 6), dpi=100)
            ax_bar = fig_bar.add_subplot(111)
            sorted_classes = sorted(filtered_class_data.items(), key=lambda x: -x[1])
            x_pos = range(len(sorted_classes))
            bar_colors = [rgb_to_hex(classification_colors.get(cls, "#888888")) for cls, _ in sorted_classes]
            ax_bar.bar(x_pos, [count for _, count in sorted_classes], color=bar_colors)
            ax_bar.set_xticks(x_pos)
            ax_bar.set_xticklabels([str(i + 1) for i in x_pos])
            ax_bar.set_title("Classification Counts")
            ax_bar.set_ylabel("Packets")

            bar_path = os.path.join(base_folder, f"classification_bar_{interval_label}.png")
            fig_bar.savefig(bar_path)
            plt.close(fig_bar)

            # --- Save Pie Chart ---
            fig_pie = plt.Figure(figsize=(6, 6), dpi=100)
            ax_pie = fig_pie.add_subplot(111)
            labels = [cls for cls, _ in sorted_classes]
            sizes = [count for _, count in sorted_classes]
            pie_colors = [rgb_to_hex(classification_colors.get(cls, "#888888")) for cls in labels]
            ax_pie.pie(sizes, labels=labels, colors=pie_colors, autopct='%1.1f%%', textprops={'fontsize': 10})
            ax_pie.set_title("Classification Distribution")

            pie_path = os.path.join(base_folder, f"classification_pie_{interval_label}.png")
            fig_pie.savefig(pie_path)
            plt.close(fig_pie)

            # --- Save Tables as CSV ---
            csv_path = os.path.join(base_folder, f"tables_{interval_label}.csv")
            with open(csv_path, mode='w', newline='') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(["Classification", "Count"])
                for cls, count in sorted_classes:
                    writer.writerow([cls, count])
                writer.writerow([])
                writer.writerow(["Packet Type", "Count"])
                for proto, count in sorted(filtered_type_data.items(), key=lambda x: -x[1]):
                    writer.writerow([proto, count])

        messagebox.showinfo("Save Summary", f"Summary and visuals saved to '{base_folder}'")

    except Exception as e:
        messagebox.showerror("Error", f"Failed to save summary:\n{e}")

def start_capture():
    global capture_running, ii, ctt, list_of_summaries
    capture_stop_event.clear()
    capture_running = True
    
    # Reset global counters
    ii = 0
    ctt = 0
    list_of_summaries.clear()

    output_box.config(state='normal')
    output_box.delete("1.0", tk.END)
    output_box.config(state='disabled')

    summary_box.config(state='normal')
    summary_box.delete("1.0", tk.END)
    summary_box.config(state='disabled')

    # Clear packet list
    list_of_packets.clear()
    
    # Start capture thread and track it globally
    global capture_thread
    capture_thread = threading.Thread(target=threaded_capture_live, daemon=True)
    capture_thread.start()
    update_gui_from_queue()

# === Build GUI ===
root = tk.Tk()
root.title("Packet Sniffer with Semantic Classification")
root.state('zoomed')

# ====== DARK THEME WITH VIBRANT ACCENTS ======
root.configure(bg='#0A0A12')  # Deep space blue-black base

style = ttk.Style()
style.theme_use('clam')

# ====== TYPOGRAPHY ======
default_font = ('Segoe UI', 10)
mono_font = ('Consolas', 9)
header_font = ('Segoe UI Semibold', 11)

# ====== FRAME STYLES ======
style.configure('TFrame', 
               background='#0A0A12',
               borderwidth=0)
style.configure('Card.TFrame',
               background='#161622',
               relief='raised',
               borderwidth=1)

# ====== LABEL STYLES ======
style.configure('TLabel', 
               background='#0A0A12',
               foreground='#E0E0FF',
               font=default_font)
style.configure('Header.TLabel',
               font=header_font,
               foreground='#00E5FF')

# ====== ENTRY/COMBOBOX STYLES ======
style.configure('TEntry',
               fieldbackground='#161622',
               foreground='#FFFFFF',
               bordercolor='#303040',
               lightcolor='#303040',
               darkcolor='#303040',
               insertcolor='#00E5FF',
               font=mono_font)

style.map('TEntry',
         fieldbackground=[('focus', '#1E1E2E')],
         foreground=[('focus', '#FFFFFF')])

style.configure('TCombobox',
               fieldbackground='#161622',
               foreground='#FFFFFF',
               selectbackground='#00E5FF',
               selectforeground='#0A0A12',
               arrowcolor='#00E5FF')

# ====== BUTTON STYLES ======
style.configure('TButton',
               background='#161622',
               foreground='#00E5FF',
               font=('Segoe UI Semibold', 10),
               borderwidth=1,
               focusthickness=3,
               focuscolor='#00E5FF',
               relief='flat')

style.map('TButton',
         background=[('active', '#252538'), 
                    ('pressed', '#00E5FF')],
         foreground=[('active', '#FFFFFF'), 
                    ('pressed', '#0A0A12')])

style.configure('Accent.TButton',
               background='#00E5FF',
               foreground='#0A0A12',
               font=('Segoe UI Bold', 10))

style.map('Accent.TButton',
         background=[('active', '#80F0FF'), 
                    ('pressed', '#00B8CC')],
         foreground=[('active', '#0A0A12'), 
                    ('pressed', '#0A0A12')])

# ====== PROGRESS BAR ======
style.configure("Cyber.Horizontal.TProgressbar",
               troughcolor='#161622',
               background='#00E5FF',
               bordercolor='#303040',
               lightcolor='#00E5FF',
               darkcolor='#00E5FF')

# ====== NOTEBOOK/TAB STYLES ======
style.configure('TNotebook',
               background='#0A0A12',
               borderwidth=0)
style.configure('TNotebook.Tab',
               background='#161622',
               foreground='#A0A0B0',
               padding=[10, 4],
               font=('Segoe UI Semibold', 9))
style.map('TNotebook.Tab',
         background=[('selected', '#252538')],
         foreground=[('selected', '#00E5FF')])

# ====== SCROLLED TEXT WIDGETS ======
text_widget_style = {
    'bg': '#161622',
    'fg': '#E0E0FF',
    'insertbackground': '#00E5FF',
    'selectbackground': '#FF2D75',
    'selectforeground': '#FFFFFF',
    'font': mono_font,
    'borderwidth': 0,
    'relief': 'flat'
}

# ====== TREEVIEW/TABLE STYLES ======
style.configure('Treeview',
               background='#161622',
               foreground='#E0E0FF',
               fieldbackground='#161622',
               rowheight=25,
               font=mono_font)
style.configure('Treeview.Heading',
               background='#252538',
               foreground='#00E5FF',
               font=('Segoe UI Semibold', 9))
style.map('Treeview',
         background=[('selected', '#FF2D75')],
         foreground=[('selected', '#FFFFFF')])

# ====== TOOLTIP STYLE ======
style.configure('Tooltip.TLabel',
               background='#252538',
               foreground='#E0E0FF',
               relief='solid',
               borderwidth=1,
               padding=5)

# --- MAIN LAYOUT ---

# Input frame at top
input_frame = ttk.Frame(root, style='Card.TFrame')
input_frame.grid(row=0, column=0, columnspan=2, padx=10, pady=10, sticky="ew")

# Interface selection
ttk.Label(input_frame, text="Select Interface:").pack(side='left', padx=(10, 5))
iface_var = tk.StringVar()
iface_combo = ttk.Combobox(input_frame, textvariable=iface_var, width=100, state='readonly')
iface_combo['values'] = list_interfaces()
iface_combo.pack(side='left', padx=(0, 15))

# Time controls
ttk.Label(input_frame, text="Total Time (min):").pack(side='left', padx=(10, 5))
total_time_entry = ttk.Entry(input_frame, width=10)
total_time_entry.pack(side='left', padx=(0, 15))

ttk.Label(input_frame, text="Segment Duration (s):").pack(side='left', padx=(10, 5))
segment_duration_entry = ttk.Entry(input_frame, width=15)
segment_duration_entry.pack(side='left', padx=(0, 10))

# Centered button container
button_container = ttk.Frame(root)
button_container.grid(row=1, column=0, columnspan=3, pady=(0, 10), sticky='nsew')

# Center the button frames within the container
center_frame = ttk.Frame(button_container)
center_frame.pack()

# Top row of buttons (centered)
button_frame_top = ttk.Frame(center_frame)
button_frame_top.pack(pady=(0, 5))

button_width = 20
button_padx = 10

capture_btn = ttk.Button(button_frame_top, text="Start Capture", command=start_capture, 
                        style='Accent.TButton', width=button_width)
capture_btn.pack(side='left', padx=button_padx )

stop_btn = ttk.Button(button_frame_top, text="Pause Capture", command=stop_capture, width=button_width)
stop_btn.pack(side='left', padx=button_padx)

res_btn = ttk.Button(button_frame_top, text="Resume Capture", command=resume_capture, width=button_width)
res_btn.pack(side='left', padx=button_padx)

terminate_btn = ttk.Button(button_frame_top, text="Stop Capture", command=terminate_capture, width=button_width)
terminate_btn.pack(side='left', padx=button_padx)

srch_btn = ttk.Button(button_frame_top, text="Search", command=open_search_window3, width=button_width)
srch_btn.pack(side='left', padx=button_padx)

button_container2 = ttk.Frame(root)
button_container2.grid(row=4, column=0, columnspan=2, pady=(0, 10), sticky='nsew')
# Center the button frames within the container
center_frame2 = ttk.Frame(button_container2)
center_frame2.pack()
# Bottom row of buttons (centered)
button_frame_bottom = ttk.Frame(center_frame2)
button_frame_bottom.pack()

save_btn = ttk.Button(button_frame_bottom, text="Save Summary", command=save_summary3, width=button_width)
save_btn.pack(side='left', padx=button_padx)

stats_btn = ttk.Button(button_frame_bottom, text="Show Statistics", command=show_statistics12, width=button_width)
stats_btn.pack(side='left', padx=button_padx)

his_btn = ttk.Button(button_frame_bottom, text="Show Full Summary", command=show_full_summary, width=button_width)
his_btn.pack(side='left', padx=button_padx)

# Text display areas with your preferred width ratio
output_frame = ttk.Frame(root, style='Card.TFrame')
output_frame.grid(row=2, column=0, padx=(10, 5), pady=(0, 10), sticky="nsew")

summary_frame = ttk.Frame(root, style='Card.TFrame')
summary_frame.grid(row=2, column=1, padx=(5, 10), pady=(0, 10), sticky="nsew")

text_widget_style = {
    'bg': '#161622',
    'fg': '#E0E0FF',
    'insertbackground': '#00E5FF',
    'selectbackground': '#FF2D75',
    'selectforeground': '#FFFFFF',
    'font': mono_font,
    'borderwidth': 0,
    'relief': 'flat'
}

output_box = scrolledtext.ScrolledText(output_frame, width=130, height=30, **text_widget_style)
output_box.pack(fill='both', expand=True, padx=5, pady=5)

summary_box = scrolledtext.ScrolledText(summary_frame, width=60, height=30, **text_widget_style)
summary_box.pack(fill='both', expand=True, padx=5, pady=5)

# Status bar and progress
status_frame = ttk.Frame(root, style='Card.TFrame')
status_frame.grid(row=5, column=0, columnspan=2, padx=10, pady=(0, 10), sticky="ew")

status_var = tk.StringVar(value="Ready")
status_bar = ttk.Label(status_frame, textvariable=status_var, anchor='w')
status_bar.pack(fill='x', padx=5, pady=5)

progress_frame = ttk.Frame(root)
progress_frame.grid(row=6, column=0, columnspan=2, pady=(0, 10), sticky='ew')

progress_var = tk.DoubleVar()
progress_bar = ttk.Progressbar(progress_frame, style="Cyber.Horizontal.TProgressbar", 
                              variable=progress_var, maximum=100)
progress_bar.pack(fill='x', padx=10, pady=(0, 5))

progress_label = ttk.Label(progress_frame, text="Progress: 0%", style='Header.TLabel')
progress_label.pack(pady=(0, 5))

# Configure grid weights for responsive layout
root.grid_columnconfigure(0, weight=2)  # Output area gets more space
root.grid_columnconfigure(1, weight=1)
root.grid_rowconfigure(2, weight=1)  # Text areas get all vertical space

# ====== TEXT TAGS FOR COLORED OUTPUT ======
output_box.tag_config('alert', foreground='#FF5555')  # Warning/error
output_box.tag_config('success', foreground='#00FFAA')  # Success
output_box.tag_config('highlight', foreground='#00E5FF')  # Important info
output_box.tag_config('data', foreground='#FF2D75')  # Data values
output_box.tag_config('meta', foreground='#A0A0B0')  # Metadata

root.mainloop()