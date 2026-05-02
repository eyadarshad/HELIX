# 🛡 Intelligent Assembly-Level Behavioral Malware Sandbox

**Combined COAL + ML Semester Project**

> Simulates 16-bit assembly programs at the register/memory level, extracts behavioral fingerprints, and classifies them as benign or malware using machine learning — with online learning for real-time adaptation.

---

## 🗂 Project Structure

```
Workspace/
├── emulator/
│   ├── cpu.py          ← Registers, memory, flags (COAL core)
│   ├── decoder.py      ← Assembly instruction parser
│   └── executor.py     ← Fetch-Decode-Execute loop
│
├── features/
│   └── extractor.py    ← Behavioral feature engine (12 features)
│
├── dataset/
│   ├── generator.py    ← Benign + malware-like program generator
│   ├── runner.py       ← Emulates all programs → saves CSV + JSON
│   └── programs/       ← Auto-generated .asm files (Week 4)
│
├── ml/
│   ├── train.py        ← LR / RF / GBT model training + ROC curves
│   ├── sequence_model.py ← LSTM / 1D CNN sequence classifier
│   ├── online_learner.py ← Incremental online learning (SGD)
│   ├── models/         ← Saved model files (.pkl, .keras)
│   └── results/        ← Plots and metric outputs
│
├── main.py             ← CLI: scan / label / demo
└── requirements.txt
```

---

## ⚙️ Supported Instructions (ISA)

| Category | Instructions |
|---|---|
| Data Transfer | `MOV` |
| Arithmetic | `ADD`, `SUB`, `MUL`, `DIV` |
| Logic | `AND`, `OR`, `XOR`, `NOT` |
| Comparison | `CMP` |
| Stack | `PUSH`, `POP` |
| Control Flow | `JMP`, `JZ`, `JNZ`, `JG`, `JL` |
| Procedures | `CALL`, `RET` |
| System | `INT`, `NOP`, `HLT` |

---

## 🧠 Behavioral Features Extracted

| # | Feature | What it captures |
|---|---|---|
| 1 | `register_volatility` | How often registers change |
| 2 | `stack_anomaly_score` | PUSH/POP imbalance |
| 3 | `max_stack_depth` | Peak stack depth |
| 4 | `control_flow_entropy` | Jump unpredictability |
| 5 | `memory_write_density` | Write frequency |
| 6 | `int_frequency` | System call rate |
| 7 | `self_modify_detected` | Code-segment overwrite |
| 8 | `unique_opcodes` | Instruction variety |
| 9 | `call_ret_imbalance` | CALL vs RET mismatch |
| 10 | `avg_flag_change_rate` | Flag toggle rate |
| 11 | `loop_density` | Backward jump ratio |
| 12 | `nop_sled_ratio` | NOP instruction ratio |

---

## 🚀 Week-by-Week Usage

### Week 2 – Test the emulator
```python
from emulator.cpu import CPU
from emulator.decoder import decode_program
from emulator.executor import Executor

prog = ["MOV AX, 10", "MOV CX, 3", "LOOP:", "SUB AX, 1", "CMP AX, 0", "JNZ LOOP", "HLT"]
cpu = CPU()
instrs, labels = decode_program(prog)
ex = Executor(cpu, instrs, labels)
trace = ex.run()
print(f"Executed {len(trace)} steps. AX = {cpu.get_reg('AX')}")
```

### Week 4 – Build the dataset
```bash
python -m dataset.runner
```

### Week 5 – Train ML models
```bash
python -m ml.train
python -m ml.sequence_model --model lstm
```

### Week 6 – Demo
```bash
# Analyze a file
python main.py scan myprogram.asm

# Label and update model
python main.py label suspicious.asm 1

# Built-in demo
python main.py demo
```

---

## 📦 Installation

```bash
pip install -r requirements.txt
# For sequence models:
pip install tensorflow
```

---

## 📊 COAL Coverage

✔ 16-bit data representation · ✔ ISA design · ✔ Addressing modes  
✔ Fetch-Decode-Execute cycle · ✔ FLAGS (ZF, CF, SF, OF) · ✔ PUSH/POP/CALL/RET  
✔ Conditional jumps · ✔ MUL/DIV · ✔ Boolean ops · ✔ Execution tracing

## 🤖 ML Coverage

✔ Feature engineering · ✔ Model comparison · ✔ Cross-validation  
✔ Precision/Recall/F1 · ✔ ROC curves · ✔ Sequence modeling (LSTM/CNN)  
✔ Online learning · ✔ Concept drift handling
