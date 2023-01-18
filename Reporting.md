
## Instructions to generate PDF using pandoc+latex


### Disclaimer

- The content is only one of many methodologies available for OSCP and general pentesting. Feel free to edit or provide feedback.
- The content is gathered from various sources and my own experiences. Special thanks to [Alexandre ZANNI](https://github.com/noraj/OSCP-Exam-Report-Template-Markdown) and [whoisflynn](https://github.com/whoisflynn/OSCP-Exam-Report-Template) for their methodologies and template.


### Installation

I tested the steps using `Windows`. Similar steps could be done for `linux`/`mac`.

- Install [pandoc](https://pandoc.org/installing.html) and [texlive](https://www.tug.org/texlive/windows.html).
- Create a folder `attachments` in same location as the input `md` file. Copy `Offsec-Logo-Header.png` and `Offsec-Logo-Title.png` to the `attachments` folder.
- Copy `eisvogel.latex` template file to any desired location.
- `yaml` frontmatter required for conversion. The content is to be used in the `md` file to be exported (at the very beginning).
- While using `tables`, manually create its caption as `: Information on table` format, in next line to table.
- Wherever a `pagebreak` is required, add the line `\newline`.


### Sample yaml frontmatter

```yaml
---
title: "OFFENSIVE SECURITY"
author: ["EMAIL", "OSID: OS-XXXXXX"]
date: "2000-01-01"
subject: "PEN-200"
keywords: [PEN200, OSCP]
subtitle: "OSCP Exam Report for OS-XXXXXX"
logo: "Offsec-Logo-Title.png"
logo-width: "75mm"
logo-header: "Offsec-Logo-Header.png"
lang: "en"
titlepage: true
titlepage-color: "1E90FF"
titlepage-text-color: "FFFAFA"
titlepage-rule-color: "FFFAFA"
titlepage-rule-height: 2
book: true
classoption: oneside
colorlinks: "ff0d8a"
linkcolor: magenta
urlcolor: magenta
toc-own-page: true
block-headings: true
lot: true
lof: true
---
```


### Generate PDF

Modify the following variables.
- `$latextemplate` - absolute location of `eisvogel.latex` file
- `$pdfoutput` - absolute location of final output file
- `$latexoutput` - optional (if required to export to latex instead of pdf to fix errors)
- `$resourcepath` - absolute location of `attachments` folder
- `$mdinput` - absolute location of input `md` file

```powershell
$latextemplate = "eisvogel.latex"
$pdfoutput = "Report.pdf"
$resourcepath = "attachments"
$mdinput = "Machine.md"
$latexoutput = "Report.tex"

cd $resourcepath
```

```powershell
pandoc --preserve-tabs --from markdown+yaml_metadata_block+hard_line_breaks+smart+backtick_code_blocks+fenced_code_blocks+escaped_line_breaks+space_in_atx_header --to pdf --table-of-contents --toc-depth 6 --top-level-division=chapter --highlight-style tango --listings --columns=50 --template $latextemplate --output $pdfoutput --resource-path=$resourcepath $mdinput
```


### Error handling

If there are errors during conversion, or the source needs to be validated, use the command below to generate `tex` file for analysis. Identify the issue and fix in the `markdown` file and repeat the conversion proces.s

```powershell
pandoc --preserve-tabs --from markdown+yaml_metadata_block+hard_line_breaks+smart+backtick_code_blocks+fenced_code_blocks+escaped_line_breaks+space_in_atx_header --to latex --table-of-contents --toc-depth 6 --top-level-division=chapter --highlight-style tango --listings --columns=50 --template $latextemplate --output $latexoutput --resource-path=$resourcepath $mdinput
```
