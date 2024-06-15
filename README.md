# CrashTalk
This repository contains the code and data for our paper, **"CrashTalk: Automated Generation of Precise, Human-Readable Descriptions of Software Security Bugs."** CrashTalk is an approach that uses static and dynamic analysis techniques to automatically infer the cause and consequences of a software crash and present diagnostic information following NIST’s recently released [Bugs Framework](https://usnistgov.github.io/BF/) taxonomy. Specifically, starting from a crash, we generate a detailed and accessible English description of the failure along with its weakness types and severity, thereby easing the burden on developers and security analysts alike. 

## Installation
Install directly from the repo
```console
$ git clone https://github.com/kedjames/CrashTalk.git
$ cd CrashTalk
$ pip install .
```

Alternatively, install an _editable_ version for development
```console
$ git clone https://github.com/kedjames/CrashTalk.git
$ cd CrashTalk
$ pip install -e '.[dev]'
```

## Usage
Given an observed crash caused by a memory-based vulnerability, we can quickly generate an English description of the failure, including its weakness types and severity. For example, [CVE-2018-16517](https://nvd.nist.gov/vuln/detail/CVE-2018-16517) is described by the NVD as follows: "asm/labels.c in Netwide Assembler (NASM) is prone to NULL Pointer Dereference, which allows the attacker to cause a denial of service via a crafted file." 

We can generate a more precise description as follows:

1. **Build the binary**: Navigate to the `CVE-2018-16517` directory within the `data` directory and execute the script `build-nasm.sh` to build the vulnerable `nasm` program.

2. **Execute the binary with the crashing input**: Run the command below to execute the binary and generate the diagnosis:

   ```console  
   zelos --mount 'x86-64',/,/ --taint --taint_output=terminal --source_code_path=<path-to-CrashTalk>/data/CVE-2018-16517/nasm-2.14rc15/ -- <path-to-CrashTalk>/data/CVE-2018-16517/nasm-2.14rc15/nasm -f elf <path-to-CrashTalk>/data/CVE-2018-16517/poc
   ```

3. After the execution completes, CrashTalk generates a diagnosis that looks similar to the example below:

    ```plaintext
    In nasm, missing code for an initialize pointer operation to valid memory at (parser.c:451) due to expression (result->label = NULL; /* Assume no label */) leads to a NULL Pointer. The NULL Pointer was dereferenced via a direct Read operation at (labels.c:64), which resulted in a NULL Pointer Dereference Memory Error. This may lead to denial of service - application crash.

    Weakness Type (1): CWE-476 => NULL Pointer Dereference

    CVSS V3 Severity: MEDIUM
    ```

Similarly, we can generate a diagnosis for [CVE-2020-27828](https://nvd.nist.gov/vuln/detail/CVE-2020-27828), which is a more complex vulnerability. The NVD describes it as follows: "There's a flaw in jasper's jpc encoder in versions prior to 2.0.23. Crafted input provided to jasper by an attacker could cause an arbitrary out-of-bounds write. This could potentially affect data confidentiality, integrity, or application availability."

To diagnose this bug, we apply the following steps:

1. **Build the binary**: Navigate to the `CVE-2020-27828` directory within the `data` directory and execute the script `build-jasper.sh` to build the vulnerable `jasper` program.

2. **Execute the binary with the crashing input**: Run the command below to execute the binary and generate the diagnosis:

   ```console 
   zelos --mount 'x86-64',/,/ --asan --taint --taint_output=terminal --source_code_path=<path-to-CrashTalk>/data/CVE-2020-27828/jasper-1.900.5/ -- <path-to-CrashTalk>/data/CVE-2020-27828/jasper-1.900.5/src/appl/jasper --input <path-to-CrashTalk>/data/CVE-2020-27828/jasper-CVE-2020-27828.pgx --output ./out --output-format jpc -O numrlvls=40
   ```

3. After the execution completes, CrashTalk generates a diagnosis that looks similar to the example below:

    ```plaintext
    In jasper, Missing Code to Verify Quantity tccp->maxrlvls in Codebase jpc_enc.c:620 results in an Inconsistent Value of (728) bytes. Subsequently, the Wrong Size (728) derived from tccp->maxrlvls was used to perform a Sequential Reposition of pointer prcheightexpns in Codebase jpc_enc.c:622, which resulted in an Over Bounds Pointer. Finally, using the Over Bounds Pointer prcheightexpns to perform a Sequential Write of Moderate data [728] bytes to Heap object of size 720 in Codebase jpc_enc.c:622 results in a final Buffer Overflow Memory Error. This may lead to data tampering, code execution, or denial of service.

    Weakness Type (1): CWE-787 => Out-of-bounds Write
    Weakness Type (2): CWE-20 => Improper Input Validation

    CVSS V3 Severity: HIGH
    ```

## Related Resources
CrashTalk utilizes the [Zelos](https://github.com/zeropointdynamics/zelos) emulation engine and its accompanying plugin, [CrasHD](https://github.com/zeropointdynamics/zelos-crashd), for conducting dataflow analysis.

## Development Details
- **Operating System**: Ubuntu 18.04.6 LTS
- **Architecture**: x86-64
- **Python**: Python 3.6.9