# grepVF
find(grep) vulnerabilities(V) &amp; fix(F)

```
.
├── LICENSE
├── README.md
├── engine
│   ├── __init__.py
│   ├── codescan
│   │   ├── __init__.py
│   │   ├── cve_checker.py
│   │   ├── entropy_checker.py
│   │   └── semantics_checker.py
│   ├── filescan
│   │   ├── __init__.py
│   │   └── file_scanner.py
│   ├── patcher
│   │   ├── __init__.py
│   │   ├── dfa.py
│   │   └── llm.py
│   └── reports
│       ├── __init__.py
│       ├── final.py
│       └── intermediate.py
├── main.py
├── requirements.txt
├── tests
└── utils
```
