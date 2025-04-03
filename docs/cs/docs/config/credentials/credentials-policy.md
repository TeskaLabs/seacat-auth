---
title: Politika přihlašovacích údajů
---

# Politika přihlašovacích údajů

Je možné nakonfigurovat, které pole přihlašovacích údajů jsou povinná pro vytváření nebo registraci nových přihlašovacích údajů. 
Můžete také specifikovat, která pole přihlašovacích údajů mohou být upravována kým.

## Konfigurace

Pro povolení vlastní konfigurace přidejte možnost `policy_file` do konfiguračního souboru služby 
a specifikujte cestu k vašemu souboru politiky:

```ini
[seacatauth:credentials]
policy_file=/path/to/credentials-policy.json
```

## Možnosti politiky

Struktura souboru politiky následuje jednoduché schéma:

```json
{
    "<field_name>": {
        "<context>": "<policy>"
    }
}
```

Je možné nakonfigurovat následující **pole**:
- `username`
- `email`
- `phone`

Pro všechna tato pole existují dvě konfigurovatelné **kontexty**: `creation` a `registration`.
Jejich **možnosti politiky** jsou:
- `disabled`: Pole není v tomto kontextu povoleno.
- `allowed`: Pole je povoleno, ale není povinné v tomto kontextu.
- `required`: Pole je v tomto kontextu povinné (a nesmí být prázdné).

Pole `email` a `phone` mají další **kontext**: `editable_by`.
Jeho **možnosti politiky** jsou:
- `nobody`: Pole není editovatelné, ani superuživateli.
- `admin_only`: Pole je editovatelné pouze superuživateli.
- `anybody`: Pole je editovatelné kýmkoli. To také umožňuje aktualizaci pole ve vlastních přihlašovacích údajích.

### Příklad souboru politiky

Následuje výchozí konfigurace politiky:

```json
{
	"username": {
		"creation": "required",
		"registration": "required"
	},
	"email": {
		"creation": "required",
		"registration": "required",
		"editable_by": "anybody"
	},
	"phone": {
		"creation": "allowed",
		"registration": "allowed",
		"editable_by": "anybody"
	}
}
```