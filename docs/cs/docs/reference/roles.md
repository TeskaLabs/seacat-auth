---
title: Role
---

# Role

## Role nájemce

Role nájemce existují a mají účinek pouze v rámci konkrétního nájemce. 
Mohou být přiřazeny pouze uživatelům, kteří jsou členy tohoto nájemce.
Jejich ID vždy začíná názvem jejich nájemce, následovaným lomítkem a názvem role (`$TENANT_ID/$ROLE_NAME`), 
například `acmecorp/admin`.

Pro úpravu oprávnění role nájemce je nutné mít přístup k prostředku `seacat:role:edit`.

## Globální role

Globální role existují nad nájemci.
Když je globální role přiřazena uživateli, má účinek ve všech nájemcích tohoto uživatele.
Jejich ID začíná hvězdičkou, následovanou lomítkem a názvem role (`*/$ROLE_NAME`), 
například `*/superuser`.

Pro úpravu oprávnění globální role je nutné mít oprávnění superuživatele.

### Globální role s propagací nájemce

Při vytváření globální role je možnost označit ji jako "Propagováno do nájemců".
Propagované globální role se chovají jako běžné globální role, navíc vytvářejí svou virtuální kopii (nebo "odkaz", abychom byli přesní) v každém nájemci.
To umožňuje definovat roli globálně, zatímco ji lze také přiřadit uživatelům nezávisle v každém nájemci.
ID takové virtuální propagované role začíná názvem jejich nájemce, následovaným lomítkem, **vlnovkou** a názvem globální role (`$TENANT_ID/~$ROLE_NAME`),
například pokud se globální role nazývá `*/reader`, její virtuální kopie v nájemci `acmecorp` bude mít ID `acmecorp/~reader`.

Oprávnění virtuálních rolí nájemce nejsou editovatelná, vždy jsou synchronizována se svou globální rolí.
Pro změnu oprávnění je nutné upravit globální roli.
Změny budou propagovány do všech nájemců.