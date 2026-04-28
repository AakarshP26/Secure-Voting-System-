import pandas as pd
import matplotlib.pyplot as plt
import os
import sys

def main():
    try:
        df1 = pd.read_csv('benchmarks/results_fast.csv')
    except Exception:
        df1 = pd.DataFrame()
        
    try:
        df2 = pd.read_csv('benchmarks/results.csv')
    except Exception:
        df2 = pd.DataFrame()
        
    df = pd.concat([df1, df2], ignore_index=True)
    if df.empty:
        print("No results found.")
        sys.exit(1)
        
    # Group by mode
    grouped = df.groupby('mode').agg({
        'handshake_ms': 'mean',
        'total_ms': 'mean',
        'bytes_sent_app': 'mean'
    }).reset_index()
    
    # Modes to display
    modes = grouped['mode'].tolist()
    handshake = grouped['handshake_ms'].tolist()
    bytes_sent = grouped['bytes_sent_app'].tolist()
    
    fig, ax1 = plt.subplots(figsize=(10, 6))
    
    color = 'tab:blue'
    ax1.set_xlabel('Key Exchange Mode', fontsize=12)
    ax1.set_ylabel('Handshake Latency (ms) [Log Scale]', color=color, fontsize=12)
    bars = ax1.bar(modes, handshake, color=color, alpha=0.7)
    ax1.tick_params(axis='y', labelcolor=color)
    ax1.set_yscale('log')
    
    # Add values on top of bars
    for bar in bars:
        yval = bar.get_height()
        ax1.text(bar.get_x() + bar.get_width()/2, yval, f"{yval:.1f}ms", ha='center', va='bottom', color=color, fontweight='bold')
    
    ax2 = ax1.twinx()  
    color = 'tab:red'
    ax2.set_ylabel('Bandwidth (Bytes Sent)', color=color, fontsize=12)
    line = ax2.plot(modes, bytes_sent, color=color, marker='o', linewidth=2, markersize=8)
    ax2.tick_params(axis='y', labelcolor=color)
    
    for i, txt in enumerate(bytes_sent):
        ax2.annotate(f"{int(txt)}B", (modes[i], bytes_sent[i]), textcoords="offset points", xytext=(0,10), ha='center', color=color, fontweight='bold')
    
    plt.title('Post-Quantum Overhead: Latency vs. Bandwidth', fontsize=16, fontweight='bold')
    fig.tight_layout()
    plt.savefig('docs/benchmark_results.png')
    print("Saved plot to docs/benchmark_results.png")

if __name__ == "__main__":
    main()
