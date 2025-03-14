import matplotlib
matplotlib.use('TkAgg')
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import tkinter as tk
import pandas as pd
import numpy as np

class NetworkVisualizer:
    def __init__(self):
        # Create Tkinter window
        self.root = tk.Tk()
        self.root.title('Network Traffic Monitor')
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # Create figure
        self.fig, (self.ax1, self.ax2) = plt.subplots(2, 1, figsize=(10, 6))
        
        # Embed figure in Tkinter window
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.root)
        self.canvas.draw()
        self.canvas.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH, expand=1)
        
        # Configure plots
        self.setup_plots()
        self.fig.tight_layout()
        
        # Initialize data storage
        self.current_df = pd.DataFrame()
        self.current_anomalies = []
        
        # Add update flag
        self.needs_update = False
        
        # Schedule first update
        self.root.after(100, self.process_updates)
        
    def setup_plots(self):
        """Configure initial plot settings"""
        self.ax1.set_title('Network Traffic')
        self.ax1.set_xlabel('Time')
        self.ax1.set_ylabel('Packets')
        self.ax1.grid(True)
        
        self.ax2.set_title('Anomalies')
        self.ax2.set_xlabel('Packet Length')
        self.ax2.set_ylabel('TTL')
        self.ax2.grid(True)
        
    def process_updates(self):
        """Process any pending updates"""
        try:
            if self.needs_update and not self.current_df.empty:
                self._redraw()
                self.needs_update = False
            
            # Schedule next update
            self.root.after(100, self.process_updates)
                
        except Exception as e:
            print(f"Update processing error: {e}")
            
    def _redraw(self):
        """Redraw the plots with current data"""
        try:
            # Clear plots
            self.ax1.clear()
            self.ax2.clear()
            self.setup_plots()
            
            # Update traffic plot
            if not self.current_df.empty:
                # Reset index before grouping to avoid mismatches
                df_clean = self.current_df.copy()
                df_clean.reset_index(drop=True, inplace=True)
                df_grouped = df_clean.groupby(pd.Grouper(key='timestamp', freq='5S')).size()
                df_grouped = df_grouped.fillna(0)  # Fill any gaps with zeros
                
                # Plot only if we have valid data
                if not df_grouped.empty:
                    self.ax1.plot(df_grouped.index, df_grouped.values, 'b-')
            
            # Update anomalies plot
            if any(self.current_anomalies):
                anomaly_df = self.current_df[self.current_anomalies]
                if not anomaly_df.empty:
                    self.ax2.scatter(anomaly_df['length'], anomaly_df['ttl'],
                                   c='red', alpha=0.5, s=50)
            
            # Refresh canvas
            self.fig.tight_layout()
            self.canvas.draw()
            
        except Exception as e:
            print(f"Redraw error: {e}")
    
    def update_plots(self, df, anomalies):
        """Update data for plotting"""
        try:
            if not df.empty:
                self.current_df = df.copy()
                self.current_anomalies = anomalies.copy()
                self.needs_update = True
                print(f"Received update: {len(df)} packets, {sum(anomalies)} anomalies")
        except Exception as e:
            print(f"Plot update error: {e}")
    
    def on_closing(self):
        """Handle window closing"""
        self.root.quit()
        self.root.destroy()
        
    def start(self):
        """Start the visualization"""
        self.root.mainloop()
    
    def stop(self):
        """Clean up resources"""
        if hasattr(self, 'root'):
            self.root.quit()
        plt.close('all')
    
    def __del__(self):
        self.stop()
