# Imported and declared Asset values are stored separately

Some Asset values can come from the CMDB Source or from a Declaration by a barbattack user. We store the imported value and the Declaration side by side and derive the effective value, rather than keeping a single field. A re-sync then updates the imported value without erasing a Declaration, and removing a Declaration falls back to the CMDB value.

## Which values

- **Asset Owner**: imported and declarable; the Declaration wins.
- **Exposure**: declared only.
- **Criticality**: imported only.
- Everything else (name, description, Asset Kind, Hardware, Software Components, status): imported only.
