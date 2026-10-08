def main():
    path = "frontend/index.html"
    with open(path, "r", encoding="utf-8") as f:
        lines = f.readlines()
        
    start_line = 3150
    end_line = 3300
    
    output_path = "scratch/frontend_js_output.txt"
    with open(output_path, "w", encoding="utf-8") as f_out:
        for idx in range(start_line - 1, min(end_line, len(lines))):
            f_out.write(f"{idx + 1}: {lines[idx]}")
    print(f"Successfully wrote lines {start_line}-{end_line} to {output_path}")

if __name__ == "__main__":
    main()
