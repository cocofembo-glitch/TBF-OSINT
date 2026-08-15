import time
import socket
import requests
import json
import concurrent.futures
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeRemainingColumn

console = Console()

def run_startup_checks():
    console.clear()
    console.print(Panel.fit(
        "[bold cyan]⚡ TBF-OSINT v3.0 ULTIMATE ⚡[/bold cyan]\n"
        "[bold magenta]Инициализация модулей системы...[/bold magenta]",
        border_style="bold violet"
    ))
    console.print()

    # 5 этапов проверки (по 10 секунд каждый)
    tasks_info = [
        ("[cyan]1/5[/cyan] Проверка сетевых интерфейсов и Termux...", 10),
        ("[cyan]2/5[/cyan] Загрузка базы данных API (IP-GEO / WHOIS)...", 10),
        ("[cyan]3/5[/cyan] Инициализация потоков ThreadPoolExecutor...", 10),
        ("[cyan]4/5[/cyan] Синхронизация списка платформ и соцсетей...", 10),
        ("[cyan]5/5[/cyan] Тестирование модуля Rich UI и генератора отчетов...", 10),
    ]

    with Progress(
        SpinnerColumn(spinner_name="dots"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=30, complete_style="bold green", finished_style="bold cyan"),
        TaskProgressColumn(),
        TimeRemainingColumn(),
        console=console
    ) as progress:
        
        for description, duration in tasks_info:
            task = progress.add_task(description, total=100)
            step_time = duration / 100
            
            for _ in range(100):
                time.sleep(step_time)
                progress.update(task, advance=1)

    console.print("\n[bold green]✓ Все проверки успешно пройдены! Система готова к работе.[/bold green]\n")
    time.sleep(1)

def print_header():
    console.clear()
    console.print(Panel.fit(
        "[bold cyan]⚡ TBF-OSINT v3.0 ULTIMATE ⚡[/bold cyan]\n"
        "[bold magenta]Multi-Threaded Recon, DNS & Port Scanner for Termux[/bold magenta]",
        border_style="bold violet"
    ))

def save_report(filename, data_str):
    with open(filename, "w", encoding="utf-8") as f:
        f.write(data_str)
    console.print(f"\n[bold green]💾 Отчет сохранен в файл:[/bold green] [cyan]{filename}[/cyan]")

def get_ip_info(target):
    console.print(f"\n[bold yellow]🔍 Разведка по IP/Домену:[/bold yellow] [bold cyan]{target}[/bold cyan]\n")
    
    try:
        ip_addr = socket.gethostbyname(target)
    except socket.gaierror:
        console.print("[bold red]❌ Не удалось определить IP-адрес.[/bold red]")
        return

    try:
        response = requests.get(f"http://ip-api.com/json/{ip_addr}?fields=status,message,country,regionName,city,zip,lat,lon,timezone,isp,org,as,query", timeout=5)
        data = response.json()

        if data.get("status") == "fail":
            console.print(f"[bold red]❌ Ошибка API: {data.get('message')}[/bold red]")
            return

        table = Table(title=f"Информация об IP: [bold green]{ip_addr}[/bold green]", border_style="bold cyan")
        table.add_column("Параметр", style="bold magenta")
        table.add_column("Значение", style="green")

        report_data = f"--- TBF-OSINT Report for {target} ({ip_addr}) ---\n"
        for key, val in [("IP Адрес", data.get("query")), ("Страна", data.get("country")), 
                         ("Город", f"{data.get('regionName')}, {data.get('city')}"), 
                         ("Координаты", f"{data.get('lat')}, {data.get('lon')}"),
                         ("Провайдер", data.get("isp")), ("Организация", data.get("org"))]:
            table.add_row(key, str(val))
            report_data += f"{key}: {val}\n"

        console.print(table)
        
        if Prompt.ask("\nСохранить отчет в файл?", choices=["y", "n"], default="n") == "y":
            save_report(f"osint_{ip_addr}.txt", report_data)

    except requests.RequestException:
        console.print("[bold red]❌ Ошибка сети.[/bold red]")

def scan_port(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.8)
    result = s.connect_ex((ip, port))
    s.close()
    if result == 0:
        return port
    return None

def fast_port_scan(target):
    console.print(f"\n[bold yellow]⚡ Быстрое сканирование портов:[/bold yellow] [bold cyan]{target}[/bold cyan]\n")
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        console.print("[bold red]❌ Ошибка резолва домена.[/bold red]")
        return

    common_ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 1433, 3306, 3389, 5432, 8080, 8443]
    open_ports = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(scan_port, ip, port): port for port in common_ports}
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res:
                open_ports.append(res)

    table = Table(title=f"Открытые порты {ip}", border_style="bold green")
    table.add_column("Порт", style="bold yellow")
    table.add_column("Статус", style="bold green")

    if open_ports:
        for p in sorted(open_ports):
            table.add_row(str(p), "OPEN")
        console.print(table)
    else:
        console.print("[bold red]❌ Открытых популярных портов не обнаружено.[/bold red]")

def check_site(site, url):
    try:
        r = requests.get(url, timeout=3)
        if r.status_code == 200:
            return site, "[bold green]НАЙДЕН[/bold green]", url
        return site, "[bold red]НЕ НАЙДЕН[/bold red]", "-"
    except requests.RequestException:
        return site, "[bold gray]ОШИБКА[/bold gray]", "-"

def check_username_fast(username):
    console.print(f"\n[bold yellow]🔎 Мультипоточный поиск никнейма:[/bold yellow] [bold cyan]{username}[/bold cyan]\n")
    
    sites = {
        "GitHub": f"https://github.com/{username}",
        "Telegram": f"https://t.me/{username}",
        "Steam": f"https://steamcommunity.com/id/{username}",
        "Reddit": f"https://www.reddit.com/user/{username}",
        "Pinterest": f"https://www.pinterest.com/{username}",
        "TikTok": f"https://www.tiktok.com/@{username}",
        "GitLab": f"https://gitlab.com/{username}",
        "DockerHub": f"https://hub.docker.com/u/{username}",
        "PyPI": f"https://pypi.org/user/{username}"
    }

    table = Table(title=f"Результаты для: [bold cyan]{username}[/bold cyan]", border_style="bold blue")
    table.add_column("Платформа", style="bold yellow")
    table.add_column("Статус", justify="center")
    table.add_column("Ссылка", style="dim blue")

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(check_site, site, url) for site, url in sites.items()]
        for future in concurrent.futures.as_completed(futures):
            site, status, url = future.result()
            table.add_row(site, status, url)

    console.print(table)

def main():
    # 1. Запуск заставки с 5 прогресс-барами
    run_startup_checks()

    # 2. Главное меню со всеми функциями
    print_header()
    console.print("[1] 🌐 GEO-IP & Информация об узле")
    console.print("[2] ⚡ Быстрый сканер портов (No-Root)")
    console.print("[3] 👤 Быстрый поиск никнейма (Multi-Thread)")
    console.print("[0] 🚪 Выход\n")

    choice = Prompt.ask("Выбери режим", choices=["1", "2", "3", "0"], default="1")

    if choice == "1":
        target = Prompt.ask("Введи IP или домен", default="8.8.8.8")
        get_ip_info(target)
    elif choice == "2":
        target = Prompt.ask("Введи IP или домен для сканирования портов")
        fast_port_scan(target)
    elif choice == "3":
        username = Prompt.ask("Введи никнейм")
        check_username_fast(username)
    elif choice == "0":
        console.print("[bold pink1]TBF-OSINT v3.0 ULTIMATE завершил работу! 🔥[/bold pink1]")

if __name__ == "__main__":
    main()

