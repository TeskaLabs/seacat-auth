---
title: Zdroje
---

# Zdroje

Zdroje jsou nejzákladnější jednotkou autorizace. Jsou to jednotlivá a specifická oprávnění k přístupu.

!!! note "Jak používat zdroje"

    * Chcete-li udělit přístup k zdrojům, seskupte zdroje do role a poté přiřaďte roli k přihlašovacím údajům. Jinými slovy, nemůžete přiřadit zdroje přímo k přihlašovacím údajům; přihlašovací údaje mohou mít přístup k zdroji pouze prostřednictvím role.
    * Můžete přiřadit stejný zdroj několika rolím.
    * Role může mít více zdrojů. Role může být přiřazena několika přihlašovacím údajům.


Na obrazovce Zdroje můžete vidět:

* ID zdroje: Název zdroje
* Popis: Uživatel vytvořený a pro člověka čitelný popis toho, jaké oprávnění zdroj uděluje
* Vytvořeno: Datum a čas, kdy byl zdroj vytvořen

## Vytvoření zdroje

1. Na obrazovce Zdroje klikněte na **Nový zdroj**.
2. Pojmenujte zdroj, zadejte krátký popis a klikněte na **Vytvořit zdroj**.

## Smazané zdroje

1. Chcete-li zobrazit smazané zdroje, klikněte na **Smazané zdroje** na obrazovce Zdroje.
2. Chcete-li obnovit zdroj (znovu ho aktivovat), klikněte na kruhovou šipku na konci řádku zdroje.

## Zahrnuté zdroje

Následující zdroje jsou automaticky k dispozici v instalaci SeaCat Auth:

* `seacat:tenant:create`: Uděluje právo vytvořit nového nájemce	
* `seacat:role:assign`: Přiřadit a odebrat role nájemce.
* `seacat:role:edit`: Vytvářet, upravovat a mazat role nájemce. To neumožňuje nositeli přiřadit zdroje systému SeaCat.	
* `seacat:role:access`: Hledat role nájemce, zobrazit podrobnosti o roli a seznam nositelů rolí.	
* `seacat:tenant:assign`: Přiřadit a odebrat členy nájemce, pozvat nové uživatele k nájemci.	
* `seacat:tenant:delete`: Smazat nájemce.	
* `seacat:tenant:edit`: Upravit údaje o nájemci.	
* `seacat:tenant:access`: Seznam nájemců, zobrazit podrobnosti o nájemci a vidět členy nájemce.	
* `seacat:client:edit`: Upravit a smazat klienty.	
* `seacat:client:access`: Seznam klientů a zobrazit podrobnosti o klientech.	
* `seacat:resource:edit`: Upravit a smazat zdroje.	
* `seacat:resource:access`: Seznam zdrojů a zobrazit podrobnosti o zdrojích.
* `seacat:session:terminate`: Ukončit relace.
* `seacat:session:access`: Seznam relací a zobrazit podrobnosti o relacích.
* `seacat:credentials:edit`: Upravit a pozastavit přihlašovací údaje.
* `seacat:credentials:access`: Seznam přihlašovacích údajů a zobrazit podrobnosti o přihlašovacích údajích.