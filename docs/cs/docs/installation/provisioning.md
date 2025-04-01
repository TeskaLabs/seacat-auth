---
title: Mód poskytování
---

# Mód poskytování

Když nainstalujete novou čistou instanci SeaCat Auth, neexistuje žádný konvenční způsob přihlášení, protože neexistují žádné uživatelské účty. Mód poskytování vytváří dočasné superuživatelské přihlašovací údaje, které lze použít k přihlášení a vytvoření běžného účtu pro sebe.

## Spuštění SeaCat Auth v módu poskytování

Existují dva způsoby, jak aktivovat mód poskytování:
- První možností je spustit `seacatauth.py` s argumentem `--provisioning`

```shell
python3 seacatauth.py -c /conf/seacatauth.conf --provisioning
```

- Druhou možností je nastavit proměnnou prostředí `SEACAT_AUTH_PROVISIONING` na `1` nebo `TRUE`, exportovat ji a spustit SeaCat Auth. To lze snadno provést v `docker-compose.yml`:

```yaml
seacat-auth-svc:
  ...
  environment:
    - SEACAT_AUTH_PROVISIONING=1
```

## Přihlášení

Když spustíte mód poskytování, následující text bude vytištěn do logu SeaCat Auth:

```
SeaCat Auth běží v módu poskytování.

Použijte následující přihlašovací údaje pro přihlášení:

	USERNAME:   superuser
	PASSWORD:   **************

```

Použijte tyto přihlašovací údaje k přihlášení.

V uživatelském rozhraní WebUI uvidíte, že byl vytvořen poskytovací nájemce a poskytovací role. Tyto jsou dočasné a budou automaticky smazány, když bude aplikace zastavena.

**`POZNÁMKA`** Přihlašovací údaje superuživatele jsou smazány a znovu vytvořeny s novým heslem pokaždé, když je aplikace restartována.

## Nastavení prostředí

- **Vytvořte nájemce.** Každý uživatel musí mít přiřazen alespoň jednoho nájemce, aby mohl vstoupit do SeaCat WebUI.
- **Vytvořte uživatelský účet.** Heslo bude odesláno prostřednictvím e-mailu nebo SMS, v závislosti na tom, jaké kontaktní informace vyplníte. **Ujistěte se, že je váš SMTP nebo SMS poskytovatel správně nastaven v konfiguraci SeaCat Auth.**
- Otevřete detail uživatele a **přiřaďte nájemce**, kterého jste vytvořili dříve, a **role `*/superuser`**.
- Nyní se můžete odhlásit z relace superuživatele poskytování.
- Zkontrolujte, zda jste obdrželi odkaz na resetování hesla pro vaše nové přihlašovací údaje. Pokračujte k resetování hesla a poté se přihlaste!

**`POZNÁMKA`** Nepřiřazujte poskytovací nájemce nebo roli superuživatele poskytování žádnému jinému uživateli, protože je dočasná a bude smazána, když bude aplikace restartována a poskytování skončí.

## Zakázání módu poskytování

Chcete-li zakázat mód poskytování, jednoduše spusťte aplikaci bez příznaku `--provisioning` a s `SEACAT_AUTH_PROVISIONING` nastaveným na `0` nebo úplně nezadaným (smazaným z `docker-compose.yml`).