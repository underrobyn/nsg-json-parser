# nsg-json-parser
Parse NSG JSON files


Usage:
```python
from nsg_parser import NSGJsonDump


def analyse(nf: NSGJsonDump):
    for row in nf.packets:
        if row.frequency == 497:
        print(f"{row.category.value} {row.direction} {row.title}")


nf = NSGJsonDump(filename=f"input/test_nsgparse.json")
nf.parse()
nf.dump()

analyse(nf)
```