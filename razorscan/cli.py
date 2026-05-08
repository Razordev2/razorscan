import typer
import asyncio
import json
from datetime import datetime
from jinja2 import Environment, FileSystemLoader
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.syntax import Syntax

from razorscan.core.requester import RazorRequester
from razorscan.modules.security_analyzer import SecurityAnalyzer
from razorscan.modules.exposure_scanner import ExposureScanner
from razorscan.modules.js_extractor import JSExtractor
from razorscan.utils.diff import AuthDiffHelper
from razorscan.modules.subdomain_intel import SubdomainIntel
from razorscan.modules.wayback_intel import WaybackIntel
from razorscan.modules.wayback_intel import WaybackIntel
from razorscan.modules.opportunity_scanner import OpportunityScanner
from razorscan.modules.cloud_finder import CloudFinder
from razorscan.modules.sitemap_parser import SitemapParser
from razorscan.modules.liferay_hunter import LiferayHunter
from razorscan.modules.secret_scanner import SecretScanner
from razorscan.modules.bypass_hunter import BypassHunter
from razorscan.modules.robots_hunter import RobotsHunter
from razorscan.modules.param_miner import ParamMiner
from razorscan.modules.sourcemap_hunter import SourceMapHunter
from razorscan.modules.s3_hunter import S3Hunter
from razorscan.modules.subdomain_hunter import SubdomainHunter
from razorscan.modules.api_hunter import APIHunter
from razorscan.modules.moodle_hunter import MoodleHunter
from razorscan.modules.wordpress_hunter import WordPressHunter
from razorscan.modules.credential_hunter import CredentialHunter

app = typer.Typer(help="Razorscan: Professional Bug Bounty Analysis Tool")
console = Console()

async def run_scan(urls: list[str], output_html: bool = False, output_json_dir: str = "reports", deep_scan: bool = False):
    requester = RazorRequester(delay=0.5) 
    import os
    if not os.path.exists(output_json_dir):
        os.makedirs(output_json_dir)

    all_targets = list(urls)
    scanned_count = 0

    while all_targets and scanned_count < (100 if deep_scan else len(urls)):
        url = all_targets.pop(0)
        scanned_count += 1
        if not requester.is_alive(url):
            console.print(f"[dim][red]![/red] Skipping {url}: DNS Resolution Failed[/dim]")
            continue

        if not url.startswith("http"):
            url = f"https://{url}"
            
        results = {"target": url, "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
        console.print(f"\n[bold blue]>>> Scanning: {url}[/bold blue]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True
        ) as progress:
            
            # Phase 14: Credential Hunting
            with console.status("[bold yellow]Hunting for Credentials & Backups...") as status:
                cred_hunter = CredentialHunter(requester)
                cred_findings = await cred_hunter.hunt(url)
                if cred_findings:
                    table = Table(title="💎 CREDENTIALS & BACKUPS FOUND", style="bold yellow")
                    table.add_column("Type", style="cyan")
                    table.add_column("URL", style="green")
                    for f in cred_findings:
                        table.add_row(f["type"], f["url"])
                    console.print(table)
                else:
                    console.print("[yellow]! No immediate backups or credential files found.[/yellow]")
            
            # Phase 1: Security Headers
            task1 = progress.add_task(description="[cyan]Analyzing Headers...", total=None)
            response = await requester.fetch(url)
            if response:
                analyzer = SecurityAnalyzer(response)
                results["security"] = analyzer.analyze()
            progress.update(task1, description="[green]Headers Analyzed!")

            # Phase 2: Exposure Scan
            task2 = progress.add_task(description="[cyan]Scanning for sensitive files...", total=None)
            scanner = ExposureScanner(requester)
            results["exposures"] = await scanner.scan(url)
            progress.update(task2, description="[green]Exposure Scan Complete!")
            # Phase 3: JS Analysis (Passive)
            task3 = progress.add_task(description="[cyan]Extracting JS Endpoints...", total=None)
            from bs4 import BeautifulSoup
            if response:
                soup = BeautifulSoup(response.text, 'html.parser')
                js_scripts = [s.get('src') for s in soup.find_all('script') if s.get('src')]
                js_results = []
                extractor = JSExtractor(requester)
                
                # Scan up to 3 JS files to be safe/fast
                for script_url in js_scripts[:3]:
                    if not script_url.startswith('http'):
                        script_url = f"{url.rstrip('/')}/{script_url.lstrip('/')}"
                    js_data = await extractor.extract_from_url(script_url)
                    
                    # Scan for secrets in JS content
                    js_response = await requester.fetch(script_url)
                    if js_response:
                        secrets = SecretScanner.scan(js_response.text)
                        if secrets:
                            js_data["secrets_found"] = secrets

                    if js_data:
                        js_results.append({"url": script_url, "data": js_data})
                results["js_analysis"] = js_results
            progress.update(task3, description="[green]JS Analysis Complete!")

            # Phase 4: Opportunity Analysis (Deep Content Scan)
            task4 = progress.add_task(description="[cyan]Analyzing Content Opportunities...", total=None)
            if response:
                opp_scanner = OpportunityScanner()
                results["opportunities"] = opp_scanner.analyze_content(response.text, url)
            progress.update(task4, description="[green]Opportunity Scan Complete!")

            # Phase 5: Cloud Bucket Hunt
            if response:
                results["cloud_buckets"] = list(CloudFinder.find_buckets(response.text))
            
            # Phase 6: Sitemap Discovery
            task6 = progress.add_task(description="[cyan]Parsing Sitemap...", total=None)
            sitemap = SitemapParser(requester)
            results["sitemap_urls"] = await sitemap.parse(url)
            if deep_scan and results["sitemap_urls"]:
                for s_url in results["sitemap_urls"]:
                    if s_url not in urls and s_url not in all_targets:
                        all_targets.append(s_url)
            progress.update(task6, description="[green]Sitemap Parsed!")

            # Phase 7: CMS Specific Hunting (Liferay)
            task7 = progress.add_task(description="[cyan]Hunting for Liferay APIs...", total=None)
            liferay = LiferayHunter(requester)
            results["liferay_findings"] = await liferay.hunt(url)
            
            # Phase 8: Bypass Audit for Protected Endpoints
            results["bypass_success"] = []
            for find in results["liferay_findings"]:
                if "Protected" in find["type"]:
                    bh = BypassHunter(requester)
                    success = await bh.try_bypass(find["url"])
                    if success:
                        results["bypass_success"].extend(success)
            progress.update(task7, description="[green]Liferay & Bypass Audit Complete!")

            # Phase 9: Robots Analysis
            task9 = progress.add_task(description="[cyan]Analyzing robots.txt...", total=None)
            rh = RobotsHunter(requester)
            results["hidden_paths"] = list(await rh.find_hidden_paths(url))
            progress.update(task9, description="[green]Robots Analysis Complete!")

            # Phase 10: Param Mining (Berburu Celah High)
            task10 = progress.add_task(description="[cyan]Mining hidden parameters...", total=None)
            pm = ParamMiner(requester)
            results["param_mining"] = await pm.mine(url)
            progress.update(task10, description="[green]Param Mining Complete!")

            # Phase 11: Source Map Hunting (Peluang High)
            task11 = progress.add_task(description="[cyan]Checking for JS Source Maps...", total=None)
            smh = SourceMapHunter(requester)
            js_urls = [res["url"] for res in results.get("js_analysis", [])]
            results["sourcemaps"] = await smh.find_maps(js_urls)
            progress.update(task11, description="[green]Source Map Check Complete!")
            # Phase 12: S3 Bucket Hunting (Peluang Critical)
            task12 = progress.add_task(description="[cyan]Hunting for S3 Buckets...", total=None)
            s3h = S3Hunter(requester)
            results["s3_buckets"] = await s3h.check_buckets(url.split("//")[-1])
            progress.update(task12, description="[green]S3 Hunting Complete!")
            # Phase 13: Moodle Specific Hunting
            task13 = progress.add_task(description="[cyan]Hunting for Moodle Vulnerabilities...", total=None)
            mh = MoodleHunter(requester)
            results["moodle_findings"] = await mh.check_moodle(url)
            progress.update(task13, description="[green]Moodle Hunting Complete!")
            # Phase 14: WordPress Specific Hunting
            task14 = progress.add_task(description="[cyan]Hunting for WordPress Vulnerabilities...", total=None)
            wph = WordPressHunter(requester)
            results["wp_findings"] = await wph.check_wordpress(url)
            progress.update(task14, description="[green]WordPress Hunting Complete!")
        # Display Results
        if results.get("exposures"):
            table = Table(title=f"Exposures: {url}", border_style="red")
            table.add_column("Path", style="bold")
            table.add_column("Status")
            for exp in results["exposures"]:
                table.add_row(exp["path"], "[red]200 OK[/red]")
            console.print(table)
        else:
            console.print(f"[dim]No critical exposures on {url}[/dim]")

        # Display Opportunities
        opps = results.get("opportunities")
        if opps and (opps["internal_ips"] or opps["keywords_found"] or opps["dangerous_params"]):
            opp_table = Table(title="💎 Vulnerability Opportunities Found", border_style="bold yellow")
            opp_table.add_column("Type", style="bold")
            opp_table.add_column("Findings", style="white")

            if opps["internal_ips"]:
                opp_table.add_row("Internal IPs", ", ".join(opps["internal_ips"]))
            if opps["keywords_found"]:
                opp_table.add_row("Sensitive Keywords", ", ".join(opps["keywords_found"]))
            if opps["dangerous_params"]:
                opp_table.add_row("Vuln Parameters", ", ".join(opps["dangerous_params"]))
            
            console.print(opp_table)

            # Display Snippets (Context)
            if opps.get("snippets"):
                with console.status("[bold yellow]Extracting context..."):
                    console.print("\n[bold]🔍 Evidence Snippets (PoC Material):[/bold]")
                    for snip in opps["snippets"][:5]: # Show top 5
                        console.print(f"  [dim]↳ {snip}[/dim]")
            
            # Display Cloud Buckets specifically
            if results.get("cloud_buckets"):
                bucket_table = Table(title="☁️ Cloud Storage Found", border_style="bold blue")
                bucket_table.add_column("Bucket URL")
                for b in results["cloud_buckets"]:
                    bucket_table.add_row(b)
                console.print(bucket_table)
                console.print("[dim]Action: Check for 'Public Access' or 'Directory Listing'.[/dim]")

            # Display Liferay Findings
            if results.get("liferay_findings"):
                liferay_table = Table(title="💎 Liferay CMS Opportunities", border_style="bold magenta")
                liferay_table.add_column("Endpoint")
                liferay_table.add_column("Type")
                for f in results["liferay_findings"]:
                    liferay_table.add_row(f["url"], f["type"])
                console.print(liferay_table)
                console.print("[dim]Critical: If /api/jsonws is open, test for unauth API calls.[/dim]")

            # Display Bypass Success
            if results.get("bypass_success"):
                bp_table = Table(title="🔓 BYPASS SUCCESSFUL!", border_style="bold green")
                bp_table.add_column("Endpoint")
                bp_table.add_column("Header Used")
                for s in results["bypass_success"]:
                    bp_table.add_row(s["url"], str(s["header"]))
                console.print(bp_table)
                console.print("[bold red]CRITICAL: Restricted endpoint accessed via header manipulation![/bold red]")

            # Display Hidden Paths from Robots
            if results.get("hidden_paths"):
                rb_table = Table(title="🕵️ Hidden Paths from robots.txt", border_style="bold cyan")
                rb_table.add_column("Path")
                for p in results["hidden_paths"]:
                    rb_table.add_row(p)
                console.print(rb_table)
                console.print("[dim]Action: Manually check these paths for lack of authentication.[/dim]")

            # Display Param Mining results
            if results.get("param_mining"):
                pm_table = Table(title="🔥 POTENTIAL HIGH VULN (Param Mining)", border_style="bold red")
                pm_table.add_column("Parameter")
                pm_table.add_column("Full URL")
                for f in results["param_mining"]:
                    pm_table.add_row(f["parameter"], f["url"])
                console.print(pm_table)
                console.print("[bold red]Action: Check if these parameters reveal sensitive data or admin panels![/bold red]")

            # Display Source Maps
            if results.get("sourcemaps"):
                sm_table = Table(title="💎 EXPOSED SOURCE MAPS (HIGH POTENTIAL)", border_style="bold yellow")
                sm_table.add_column("URL")
                for s in results["sourcemaps"]:
                    sm_table.add_row(s["url"])
                console.print(sm_table)
                console.print("[bold yellow]CRITICAL: Original source code can be recovered from these maps![/bold yellow]")

            # Display S3 Buckets
            if results.get("s3_buckets"):
                s3_table = Table(title="🪣 DISCOVERED S3 BUCKETS", border_style="bold blue")
                s3_table.add_column("Bucket Name")
                s3_table.add_column("URL")
                s3_table.add_column("Status")
                for s in results["s3_buckets"]:
                    s3_table.add_row(s["bucket"], s["url"], s["status"])
                console.print(s3_table)
                console.print("[bold red]CRITICAL: Check if sensitive files are accessible in these buckets![/bold red]")

            # Display Moodle Findings
            if results.get("moodle_findings"):
                mdl_table = Table(title="🎓 MOODLE VULNERABILITIES FOUND", border_style="bold magenta")
                mdl_table.add_column("Type", style="cyan")
                mdl_table.add_column("URL", style="green")
                for m in results["moodle_findings"]:
                    mdl_table.add_row(m["type"], m["url"])
                console.print(mdl_table)
                console.print("[bold red]Action: These files often contain version info or DB schemas![/bold red]")

            # Display WordPress Findings
            if results.get("wp_findings"):
                wp_table = Table(title="📝 WORDPRESS VULNERABILITIES FOUND", border_style="bold blue")
                wp_table.add_column("Type", style="cyan")
                wp_table.add_column("Detail", style="green")
                wp_table.add_column("URL", style="dim")
                for w in results["wp_findings"]:
                    wp_table.add_row(w["type"], w["detail"], w["url"])
                console.print(wp_table)
                console.print("[bold red]Action: Enumerated users and active XML-RPC are high-risk findings![/bold red]")

            # Display Secrets Found in JS
            for js_res in results.get("js_analysis", []):
                secrets = js_res["data"].get("secrets_found")
                if secrets:
                    sec_table = Table(title=f"🔑 Secrets Found in {js_res['url']}", border_style="bold red")
                    sec_table.add_column("Type")
                    sec_table.add_column("Snippet")
                    for s in secrets:
                        sec_table.add_row(s["type"], s["snippet"])
                    console.print(sec_table)

            console.print("[dim]Note: These are manual testing candidates. High potential for IDOR/SSRF.[/dim]")


        # Export individual JSON
        filename = url.replace("https://", "").replace("http://", "").replace("/", "_")
        with open(f"{output_json_dir}/{filename}.json", "w") as f:
            json.dump(results, f, indent=4)


    if output_html:
        env = Environment(loader=FileSystemLoader('templates'))
        template = env.get_template('report.html')
        html_out = template.render(results)
        with open("report_output.html", "w") as f:
            f.write(html_out)
        console.print("[blue]HTML report generated: report_output.html[/blue]")

@app.command()
def diff(
    file1: str = typer.Argument(..., help="Path to first JSON response"),
    file2: str = typer.Argument(..., help="Path to second JSON response")
):
    """Compare two JSON responses to identify IDOR/Auth issues."""
    try:
        with open(file1) as f1, open(file2) as f2:
            data1 = json.load(f1)
            data2 = json.load(f2)
        
        diff_data = AuthDiffHelper.compare_json(data1, data2)
        
        table = Table(title="IDOR / Response Difference Report")
        table.add_column("Field", style="cyan")
        table.add_column("Response 1", style="red")
        table.add_column("Response 2", style="green")

        for key, val in diff_data["different_values"].items():
            table.add_row(key, str(val["resp1"]), str(val["resp2"]))
        
        console.print(table)
        
        if diff_data["identical_keys"]:
            console.print(f"\n[yellow]Identical fields (potential leakage):[/yellow] {', '.join(diff_data['identical_keys'])}")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")

@app.command()
def scan(
    targets: list[str] = typer.Argument(..., help="List of target URLs"),
    html: bool = typer.Option(False, help="Generate HTML report"),
    json_dir: str = typer.Option("reports", help="Directory to save JSON results"),
    deep: bool = typer.Option(False, help="Deep scan all URLs in sitemap")
):
    """Start a batch analysis scan on multiple targets."""
    console.print(Panel.fit("🚀 Razorscan v1.3 - Hunter Edition", style="bold magenta"))
    asyncio.run(run_scan(targets, html, json_dir, deep_scan=deep))


@app.command()
def intel(domain: str = typer.Argument(..., help="Domain to research")):
    """Perform passive reconnaissance (Subdomains + Wayback Machine)."""
    requester = RazorRequester(delay=0.1) # Fast for public APIs
    
    async def run_intel():
        console.print(Panel(f"Running Passive Intel for: [bold]{domain}[/bold]", style="blue"))
        
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
            # Subdomains
            task1 = progress.add_task(description="Enumerating subdomains (crt.sh)...", total=None)
            sub_intel = SubdomainIntel(requester)
            subs = await sub_intel.discover(domain)
            progress.update(task1, description=f"[green]Found {len(subs)} subdomains!")
            
            # Wayback
            task2 = progress.add_task(description="Extracting historical URLs (Wayback)...", total=None)
            wayback = WaybackIntel(requester)
            urls = await wayback.get_urls(domain)
            progress.update(task2, description=f"[green]Found {len(urls)} historical URLs!")

        # Display Subdomains
        if subs:
            sub_table = Table(title="Subdomain Discovery", show_lines=True)
            sub_table.add_column("Subdomain", style="cyan")
            for s in sorted(list(subs))[:15]: # Show first 15
                sub_table.add_row(s)
            console.print(sub_table)
            if len(subs) > 15:
                console.print(f"[dim]... and {len(subs)-15} more.[/dim]")

        # Display Wayback (Looking for parameters)
        param_urls = [u for u in urls if "?" in u]
        if param_urls:
            url_table = Table(title="Interesting URLs (with parameters)", border_style="yellow")
            url_table.add_column("URL", overflow="fold")
            for u in sorted(param_urls)[:10]:
                url_table.add_row(u)
            console.print(url_table)

    asyncio.run(run_intel())

@app.command()
def request(
    url: str = typer.Argument(..., help="URL to request"),
    method: str = typer.Option("GET", help="HTTP Method (GET, POST, PUT, etc.)"),
    header: list[str] = typer.Option(None, help="Custom headers in 'Key: Value' format"),
    data: str = typer.Option(None, help="Request body data (for POST/PUT)")
):
    """Manual request interactor (CLI Repeater)."""
    requester = RazorRequester()
    
    # Parse headers
    custom_headers = {}
    if header:
        for h in header:
            if ":" in h:
                k, v = h.split(":", 1)
                custom_headers[k.strip()] = v.strip()

    async def do_request():
        console.print(f"[bold blue]Sending {method} request to {url}...[/bold blue]")
        resp = await requester.fetch(url, method=method, headers=custom_headers, content=data)
        
        if resp:
            # Display Status & Headers
            console.print(Panel(f"Status: [bold green]{resp.status_code}[/bold green]\n" + 
                              "\n".join([f"[cyan]{k}[/cyan]: {v}" for k, v in resp.headers.items()]), 
                              title="Response Headers"))
            
            # Display Body with Syntax Highlighting
            content_type = resp.headers.get("Content-Type", "")
            lexer = "json" if "json" in content_type else "html"
            
            syntax = Syntax(resp.text[:2000], lexer, theme="monokai", line_numbers=True)
            console.print(Panel(syntax, title="Response Body (Preview)"))
            if len(resp.text) > 2000:
                console.print("[dim]... truncated ...[/dim]")
        else:
            console.print("[red]Failed to get response.[/red]")

    asyncio.run(do_request())

@app.command()
def subdomains(domain: str):
    """Enumerate subdomains using crt.sh."""
    console.print(Panel.fit(f"🔍 Enumerating Subdomains for {domain}", style="bold cyan"))
    sh = SubdomainHunter()
    
    async def run():
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            progress.add_task(description="Fetching certificate logs...", total=None)
            subs = await sh.find_subdomains(domain)
            
            if subs:
                table = Table(title=f"Subdomains of {domain}", border_style="cyan")
                table.add_column("Subdomain", style="green")
                for s in sorted(subs):
                    table.add_row(s)
                console.print(table)
                console.print(f"\n[bold green]Total: {len(subs)} subdomains found.[/bold green]")
                console.print("[dim]Action: Run 'scan' on interesting subdomains like dev, staging, or admin.[/dim]")
            else:
                console.print("[yellow]No subdomains found in crt.sh logs.[/yellow]")

    asyncio.run(run())

@app.command()
def wayback(domain: str):
    """Fetch historical URLs from Wayback Machine."""
    console.print(Panel.fit(f"📜 Fetching Historical Intel for {domain}", style="bold yellow"))
    requester = RazorRequester()
    wi = WaybackIntel(requester)
    
    async def run():
        urls = await wi.fetch_urls(domain)
        if urls:
            table = Table(title=f"Wayback Discovery: {domain}", border_style="yellow")
            table.add_column("Historical URL", style="cyan", no_wrap=True)
            # Tampilkan 20 hasil teratas agar tidak kepanjangan
            for url in list(urls)[:20]:
                table.add_row(url)
            console.print(table)
            console.print(f"\n[bold green]Total: {len(urls)} historical URLs found.[/bold green]")
        else:
            console.print("[red]No historical records found.[/red]")

    asyncio.run(run())

@app.command()
def api_audit(target: str):
    """Audit an API endpoint for exposed documentation."""
    if not target.startswith("http"):
        target = f"https://{target}"
    
    console.print(Panel.fit(f"📡 Auditing API: {target}", style="bold green"))
    requester = RazorRequester()
    ah = APIHunter(requester)
    
    async def run():
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            progress.add_task(description="Hunting for API Documentation...", total=None)
            docs = await ah.find_docs(target)
            
            if docs:
                table = Table(title="Exposed API Documentation", border_style="green")
                table.add_column("Type", style="cyan")
                table.add_column("URL", style="green")
                for d in docs:
                    table.add_row(d["type"], d["url"])
                console.print(table)
                console.print("\n[bold red]CRITICAL: Exposed API docs can lead to Full API Exploitation![/bold red]")
            else:
                console.print("[yellow]No public API documentation found.[/yellow]")

    asyncio.run(run())

def show_menu():
    """Display a premium interactive menu."""
    from rich.prompt import Prompt
    from rich.layout import Layout
    from rich.live import Live
    from rich import box
    
    while True:
        console.clear()
        banner = """
[bold red]  _____   ____  ______ ____  _____   _____  _____          _   _ 
 |  __ \ / __ \|___  /|  _ \ / __ \ / ____|/ ____|   /\   | \ | |
 | |__) | |  | |  / / | |_) | |  | | (___ | |       /  \  |  \| |
 |  _  /| |  | | / /  |  _ <| |  | |\___ \| |      / /\ \ | . ` |
 | | \ \| |__| |/ /__ | |_) | |__| |____) | |____ / ____ \| |\  |
 |_|  \_\\\\____//_____||____/ \____/|_____/ \_____/_/    \_\_| \_|
[/bold red]
[bold cyan]    >>> Professional Security Auditing & Bug Bounty Suite <<<[/bold cyan]
        """
        console.print(Panel(banner, style="bold white", box=box.DOUBLE))
        
        menu_table = Table(show_header=False, box=box.SIMPLE, expand=True)
        menu_table.add_column("Option", style="bold yellow", width=5)
        menu_table.add_column("Description", style="white")
        
        menu_table.add_row("1", "🚀 [bold]Full Target Scan[/bold] (Comprehensive vulnerability audit)")
        menu_table.add_row("2", "🔍 [bold]Passive Intel[/bold] (Subdomains + Wayback Machine)")
        menu_table.add_row("3", "📡 [bold]API Documentation Hunter[/bold] (Find exposed Swagger/Postman)")
        menu_table.add_row("4", "📝 [bold]WordPress Security Audit[/bold] (Users, XML-RPC, Plugins)")
        menu_table.add_row("5", "🎓 [bold]Moodle Security Check[/bold] (Vulnerabilities & Exposures)")
        menu_table.add_row("6", "💎 [bold]Credential & Backup Hunter[/bold] (Config files, .env, backups)")
        menu_table.add_row("7", "🪣 [bold]S3 Bucket Scanner[/bold] (Public buckets discovery)")
        menu_table.add_row("8", "⚡ [bold]Manual HTTP Repeater[/bold] (Custom requests)")
        menu_table.add_row("9", "📊 [bold]JSON Diff Tool[/bold] (Identify IDOR/Auth bypass)")
        menu_table.add_row("0", "❌ [bold red]Exit[/bold red]")
        
        console.print(Panel(menu_table, title="[bold blue]MAIN MENU[/bold blue]", border_style="blue"))
        
        choice = Prompt.ask("[bold yellow]Choose an option[/bold yellow]", choices=["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"], default="0")
        
        if choice == "0":
            console.print("[bold red]Exiting Razorscan. Happy Hunting![/bold red]")
            break
        elif choice == "1":
            target = Prompt.ask("[bold cyan]Enter target URL[/bold cyan]")
            if target:
                asyncio.run(run_scan([target]))
                Prompt.ask("\n[dim]Press Enter to return to menu...[/dim]")
        elif choice == "2":
            domain = Prompt.ask("[bold cyan]Enter domain (e.g., example.com)[/bold cyan]")
            if domain:
                intel(domain)
                Prompt.ask("\n[dim]Press Enter to return to menu...[/dim]")
        elif choice == "3":
            target = Prompt.ask("[bold cyan]Enter API URL/Domain[/bold cyan]")
            if target:
                api_audit(target)
                Prompt.ask("\n[dim]Press Enter to return to menu...[/dim]")
        elif choice == "4":
            target = Prompt.ask("[bold cyan]Enter WordPress URL[/bold cyan]")
            if target:
                # WordPress specific logic
                from razorscan.modules.wordpress_hunter import WordPressHunter
                from razorscan.core.requester import RazorRequester
                async def wp_run():
                    req = RazorRequester()
                    wph = WordPressHunter(req)
                    res = await wph.check_wordpress(target)
                    if res:
                        t = Table(title="WordPress Findings")
                        t.add_column("Type")
                        t.add_row(str(res))
                        console.print(t)
                asyncio.run(wp_run())
                Prompt.ask("\n[dim]Press Enter to return to menu...[/dim]")
        elif choice == "5":
            target = Prompt.ask("[bold cyan]Enter Moodle URL[/bold cyan]")
            if target:
                from razorscan.modules.moodle_hunter import MoodleHunter
                from razorscan.core.requester import RazorRequester
                async def moodle_run():
                    req = RazorRequester()
                    mh = MoodleHunter(req)
                    res = await mh.check_moodle(target)
                    if res:
                        t = Table(title="Moodle Findings")
                        t.add_column("Type")
                        t.add_column("URL")
                        for m in res:
                            t.add_row(m["type"], m["url"])
                        console.print(t)
                asyncio.run(moodle_run())
                Prompt.ask("\n[dim]Press Enter to return to menu...[/dim]")
        elif choice == "6":
            target = Prompt.ask("[bold cyan]Enter Target URL[/bold cyan]")
            if target:
                from razorscan.modules.credential_hunter import CredentialHunter
                from razorscan.core.requester import RazorRequester
                async def cred_run():
                    req = RazorRequester()
                    ch = CredentialHunter(req)
                    res = await ch.hunt(target)
                    if res:
                        t = Table(title="Credential/Backup Findings")
                        t.add_column("Type")
                        t.add_column("URL")
                        for c in res:
                            t.add_row(c["type"], c["url"])
                        console.print(t)
                asyncio.run(cred_run())
                Prompt.ask("\n[dim]Press Enter to return to menu...[/dim]")
        elif choice == "7":
            domain = Prompt.ask("[bold cyan]Enter Domain Name[/bold cyan]")
            if domain:
                from razorscan.modules.s3_hunter import S3Hunter
                from razorscan.core.requester import RazorRequester
                async def s3_run():
                    req = RazorRequester()
                    s3h = S3Hunter(req)
                    res = await s3h.check_buckets(domain)
                    if res:
                        t = Table(title="S3 Bucket Findings")
                        t.add_column("Bucket")
                        t.add_column("URL")
                        t.add_column("Status")
                        for r in res:
                            t.add_row(r["bucket"], r["url"], r["status"])
                        console.print(t)
                asyncio.run(s3_run())
                Prompt.ask("\n[dim]Press Enter to return to menu...[/dim]")
        elif choice == "8":
            url = Prompt.ask("[bold cyan]Enter URL[/bold cyan]")
            if url:
                request(url)
                Prompt.ask("\n[dim]Press Enter to return to menu...[/dim]")
        elif choice == "9":
            file1 = Prompt.ask("[bold cyan]Enter Path to JSON 1[/bold cyan]")
            file2 = Prompt.ask("[bold cyan]Enter Path to JSON 2[/bold cyan]")
            if file1 and file2:
                diff(file1, file2)
                Prompt.ask("\n[dim]Press Enter to return to menu...[/dim]")

@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    """If no command is provided, show the interactive menu."""
    if ctx.invoked_subcommand is None:
        show_menu()

if __name__ == "__main__":
    app()

