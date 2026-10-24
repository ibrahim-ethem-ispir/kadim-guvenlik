// Teknoloji Tespit Motoru v2.0 - Enterprise Grade Fingerprinting
// ================================================================
// Wappalyzer++: 200+ teknoloji, gelişmiş sürüm tespiti, multi-pattern matching
// Web sunucularından (nginx, Apache, IIS) JavaScript framework'lerine kadar kapsamlı tespit

use scraper::{Html, Selector};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use once_cell::sync::Lazy;
use regex::Regex;

/// Tespit edilen teknoloji bilgisi (JSON üzerinden paylaşılır)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Technology {
    pub name: String,
    pub version: Option<String>,
    pub category: String,
    pub confidence: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub website: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpe: Option<String>,
}

#[derive(Debug, Clone)]
struct TechSignature {
    name: &'static str,
    category: &'static str,
    website: Option<&'static str>,
    cpe: Option<&'static str>,
    patterns: Vec<SignaturePattern>,
}

#[derive(Debug, Clone)]
enum SignaturePattern {
    Header {
        key: &'static str,
        regex: &'static str,
        confidence: u8,
        version_group: Option<usize>,
    },
    HtmlMeta {
        name: &'static str,
        content_regex: &'static str,
        confidence: u8,
        version_group: Option<usize>,
    },
    ScriptSrc {
        regex: &'static str,
        confidence: u8,
        version_group: Option<usize>,
    },
    Cookie {
        name: &'static str,
        confidence: u8,
    },
    HtmlContent {
        regex: &'static str,
        confidence: u8,
        version_group: Option<usize>,
    },
    LinkHref {
        regex: &'static str,
        confidence: u8,
        version_group: Option<usize>,
    },
    Favicon {
        hash: &'static str,
        confidence: u8,
    },
}

// Türkçe: Genişletilmiş teknoloji imza veritabanı - 100+ teknoloji signature
static TECH_SIGNATURES: Lazy<Vec<TechSignature>> = Lazy::new(|| {
    vec![
        // ===== Web Servers (Gelişmiş Sürüm Tespiti) =====
        TechSignature {
            name: "Nginx",
            category: "Web Server",
            website: Some("https://nginx.org"),
            cpe: Some("cpe:2.3:a:f5:nginx"),
            patterns: vec![
                SignaturePattern::Header { key: "server", regex: r"nginx(?:/([\d.]+))?", confidence: 100, version_group: Some(1) },
                SignaturePattern::Header { key: "server", regex: r"nginx", confidence: 90, version_group: None },
                SignaturePattern::HtmlContent { regex: r"<center>nginx(?:/([\d.]+))?</center>", confidence: 95, version_group: Some(1) },
                SignaturePattern::HtmlContent { regex: r"<hr><center>nginx</center>", confidence: 90, version_group: None },
            ],
        },
        TechSignature {
            name: "Apache",
            category: "Web Server",
            website: Some("https://httpd.apache.org"),
            cpe: Some("cpe:2.3:a:apache:http_server"),
            patterns: vec![
                SignaturePattern::Header { key: "server", regex: r"Apache(?:/([\d.]+))?", confidence: 100, version_group: Some(1) },
                SignaturePattern::Header { key: "server", regex: r"Apache", confidence: 90, version_group: None },
                SignaturePattern::HtmlContent { regex: r"<address>Apache(?:/([\d.]+))? Server", confidence: 95, version_group: Some(1) },
            ],
        },
        TechSignature {
            name: "IIS",
            category: "Web Server",
            website: Some("https://www.iis.net"),
            cpe: Some("cpe:2.3:a:microsoft:internet_information_services"),
            patterns: vec![
                SignaturePattern::Header { key: "server", regex: r"Microsoft-IIS(?:/([\d.]+))?", confidence: 100, version_group: Some(1) },
                SignaturePattern::Header { key: "x-powered-by", regex: r"ASP\.NET", confidence: 80, version_group: None },
            ],
        },
        TechSignature {
            name: "LiteSpeed",
            category: "Web Server",
            website: Some("https://www.litespeedtech.com"),
            cpe: Some("cpe:2.3:a:litespeedtech:litespeed_web_server"),
            patterns: vec![
                SignaturePattern::Header { key: "server", regex: r"LiteSpeed(?:/([\d.]+))?", confidence: 100, version_group: Some(1) },
            ],
        },
        TechSignature {
            name: "Caddy",
            category: "Web Server",
            website: Some("https://caddyserver.com"),
            cpe: Some("cpe:2.3:a:caddyserver:caddy"),
            patterns: vec![
                SignaturePattern::Header { key: "server", regex: r"Caddy", confidence: 95, version_group: None },
            ],
        },
        TechSignature {
            name: "OpenResty",
            category: "Web Server",
            website: Some("https://openresty.org"),
            cpe: Some("cpe:2.3:a:openresty:openresty"),
            patterns: vec![
                SignaturePattern::Header { key: "server", regex: r"openresty(?:/([\d.]+))?", confidence: 100, version_group: Some(1) },
            ],
        },

        // ===== Modern JavaScript Frameworks =====
        TechSignature {
            name: "Next.js",
            category: "JavaScript Framework",
            website: Some("https://nextjs.org"),
            cpe: Some("cpe:2.3:a:vercel:next.js"),
            patterns: vec![
                SignaturePattern::ScriptSrc { regex: r"_next/static", confidence: 95, version_group: None },
                SignaturePattern::HtmlMeta { name: "generator", content_regex: r"Next\.js\s*([\d.]+)?", confidence: 90, version_group: Some(1) },
                SignaturePattern::HtmlContent { regex: r"__NEXT_DATA__", confidence: 85, version_group: None },
                SignaturePattern::Header { key: "x-nextjs-page", regex: r".*", confidence: 95, version_group: None },
            ],
        },
        TechSignature {
            name: "Nuxt.js",
            category: "JavaScript Framework",
            website: Some("https://nuxt.com"),
            cpe: Some("cpe:2.3:a:nuxt:nuxt.js"),
            patterns: vec![
                SignaturePattern::ScriptSrc { regex: r"_nuxt/", confidence: 95, version_group: None },
                SignaturePattern::HtmlMeta { name: "generator", content_regex: r"Nuxt\.js\s*v?([\d.]+)?", confidence: 90, version_group: Some(1) },
                SignaturePattern::HtmlContent { regex: r"__NUXT__", confidence: 85, version_group: None },
            ],
        },
        TechSignature {
            name: "Remix",
            category: "JavaScript Framework",
            website: Some("https://remix.run"),
            cpe: None,
            patterns: vec![
                SignaturePattern::ScriptSrc { regex: r"build/_shared/", confidence: 90, version_group: None },
                SignaturePattern::HtmlContent { regex: r"window\.__remixContext", confidence: 90, version_group: None },
                SignaturePattern::HtmlMeta { name: "generator", content_regex: r"Remix", confidence: 85, version_group: None },
            ],
        },
        TechSignature {
            name: "Astro",
            category: "JavaScript Framework",
            website: Some("https://astro.build"),
            cpe: None,
            patterns: vec![
                SignaturePattern::HtmlMeta { name: "generator", content_regex: r"Astro\s*v?([\d.]+)?", confidence: 95, version_group: Some(1) },
                SignaturePattern::HtmlContent { regex: r"astro-[\w-]+", confidence: 80, version_group: None },
            ],
        },
        TechSignature {
            name: "SvelteKit",
            category: "JavaScript Framework",
            website: Some("https://kit.svelte.dev"),
            cpe: None,
            patterns: vec![
                SignaturePattern::ScriptSrc { regex: r"_app/immutable/", confidence: 95, version_group: None },
                SignaturePattern::HtmlMeta { name: "generator", content_regex: r"SvelteKit", confidence: 90, version_group: None },
                SignaturePattern::HtmlContent { regex: r"__sveltekit_", confidence: 85, version_group: None },
            ],
        },
        TechSignature {
            name: "Alpine.js",
            category: "JavaScript Framework",
            website: Some("https://alpinejs.dev"),
            cpe: None,
            patterns: vec![
                SignaturePattern::ScriptSrc { regex: r"alpine(?:\.min)?\.js", confidence: 90, version_group: None },
                SignaturePattern::HtmlContent { regex: r"x-data", confidence: 85, version_group: None },
            ],
        },

        // ===== Classic Frameworks =====
        TechSignature {
            name: "React",
            category: "JavaScript Library",
            website: Some("https://react.dev"),
            cpe: Some("cpe:2.3:a:facebook:react"),
            patterns: vec![
                SignaturePattern::ScriptSrc { regex: r"react(?:\.min)?\.js", confidence: 90, version_group: None },
                SignaturePattern::HtmlContent { regex: r"__REACT_DEVTOOLS_GLOBAL_HOOK__|data-reactroot|data-reactid", confidence: 85, version_group: None },
            ],
        },
        TechSignature {
            name: "Vue.js",
            category: "JavaScript Framework",
            website: Some("https://vuejs.org"),
            cpe: Some("cpe:2.3:a:vuejs:vue.js"),
            patterns: vec![
                SignaturePattern::ScriptSrc { regex: r"vue(?:\.min)?\.js(?:\?v=([\d.]+))?", confidence: 90, version_group: Some(1) },
                SignaturePattern::HtmlContent { regex: r"data-v-[\da-f]{8}", confidence: 85, version_group: None },
                SignaturePattern::HtmlContent { regex: r"__VUE__", confidence: 80, version_group: None },
            ],
        },
        TechSignature {
            name: "Angular",
            category: "JavaScript Framework",
            website: Some("https://angular.io"),
            cpe: Some("cpe:2.3:a:angular:angular.js"),
            patterns: vec![
                SignaturePattern::ScriptSrc { regex: r"angular(?:\.min)?\.js", confidence: 90, version_group: None },
                SignaturePattern::HtmlContent { regex: r"ng-version|ng-app|_ngcontent", confidence: 85, version_group: None },
            ],
        },
        TechSignature {
            name: "jQuery",
            category: "JavaScript Library",
            website: Some("https://jquery.com"),
            cpe: Some("cpe:2.3:a:jquery:jquery"),
            patterns: vec![
                SignaturePattern::ScriptSrc { regex: r"jquery[.-]([\d.]+)(?:\.min)?\.js", confidence: 95, version_group: Some(1) },
                SignaturePattern::ScriptSrc { regex: r"jquery", confidence: 80, version_group: None },
            ],
        },
        TechSignature {
            name: "Backbone.js",
            category: "JavaScript Library",
            website: Some("https://backbonejs.org"),
            cpe: Some("cpe:2.3:a:backbonejs:backbone"),
            patterns: vec![
                SignaturePattern::ScriptSrc { regex: r"backbone(?:\.min)?\.js", confidence: 90, version_group: None },
            ],
        },

        // ===== CSS Frameworks =====
        TechSignature {
            name: "Tailwind CSS",
            category: "CSS Framework",
            website: Some("https://tailwindcss.com"),
            cpe: None,
            patterns: vec![
                SignaturePattern::HtmlContent { regex: r#"class="[^"]*(?:flex|grid|bg-|text-|p-|m-|w-|h-)[a-z0-9-]*"#, confidence: 70, version_group: None },
                SignaturePattern::ScriptSrc { regex: r"tailwind", confidence: 85, version_group: None },
            ],
        },
        TechSignature {
            name: "Bootstrap",
            category: "CSS Framework",
            website: Some("https://getbootstrap.com"),
            cpe: Some("cpe:2.3:a:getbootstrap:bootstrap"),
            patterns: vec![
                SignaturePattern::ScriptSrc { regex: r"bootstrap(?:\.min)?\.js", confidence: 90, version_group: None },
                SignaturePattern::HtmlContent { regex: r#"class="[^"]*\b(?:container|row|col-|btn-)"#, confidence: 75, version_group: None },
                SignaturePattern::HtmlContent { regex: r"bootstrap(?:-([\d.]+))?(?:\.min)?\.css", confidence: 85, version_group: Some(1) },
            ],
        },
        TechSignature {
            name: "Bulma",
            category: "CSS Framework",
            website: Some("https://bulma.io"),
            cpe: None,
            patterns: vec![
                SignaturePattern::HtmlContent { regex: r#"class="[^"]*\b(?:section|hero|column|button)"#, confidence: 70, version_group: None },
                SignaturePattern::LinkHref { regex: r"bulma(?:\.min)?\.css", confidence: 85, version_group: None },
            ],
        },

        // ===== CMS Platforms =====
        TechSignature {
            name: "WordPress",
            category: "CMS",
            website: Some("https://wordpress.org"),
            cpe: Some("cpe:2.3:a:wordpress:wordpress"),
            patterns: vec![
                SignaturePattern::HtmlMeta { name: "generator", content_regex: r"WordPress\s*([\d.]+)?", confidence: 95, version_group: Some(1) },
                SignaturePattern::ScriptSrc { regex: r"wp-content|wp-includes", confidence: 90, version_group: None },
                SignaturePattern::HtmlContent { regex: r"wp-json", confidence: 85, version_group: None },
                SignaturePattern::LinkHref { regex: r"wp-content", confidence: 90, version_group: None },
            ],
        },
        TechSignature {
            name: "Drupal",
            category: "CMS",
            website: Some("https://www.drupal.org"),
            cpe: Some("cpe:2.3:a:drupal:drupal"),
            patterns: vec![
                SignaturePattern::HtmlMeta { name: "generator", content_regex: r"Drupal\s*([\d.]+)?", confidence: 95, version_group: Some(1) },
                SignaturePattern::ScriptSrc { regex: r"/sites/default/files", confidence: 85, version_group: None },
                SignaturePattern::Cookie { name: "SSESS", confidence: 90 },
            ],
        },
        TechSignature {
            name: "Joomla",
            category: "CMS",
            website: Some("https://www.joomla.org"),
            cpe: Some("cpe:2.3:a:joomla:joomla"),
            patterns: vec![
                SignaturePattern::HtmlMeta { name: "generator", content_regex: r"Joomla!\s*([\d.]+)?", confidence: 95, version_group: Some(1) },
                SignaturePattern::ScriptSrc { regex: r"/media/jui/", confidence: 85, version_group: None },
            ],
        },
        TechSignature {
            name: "Wix",
            category: "CMS",
            website: Some("https://www.wix.com"),
            cpe: None,
            patterns: vec![
                SignaturePattern::HtmlMeta { name: "generator", content_regex: r"Wix\.com Website Builder", confidence: 95, version_group: None },
                SignaturePattern::Header { key: "x-wix-request-id", regex: r".*", confidence: 95, version_group: None },
            ],
        },
        TechSignature {
            name: "Squarespace",
            category: "CMS",
            website: Some("https://www.squarespace.com"),
            cpe: None,
            patterns: vec![
                SignaturePattern::Header { key: "x-served-by", regex: r"squarespace", confidence: 95, version_group: None },
                SignaturePattern::HtmlContent { regex: r"static\.squarespace\.com", confidence: 90, version_group: None },
            ],
        },

        // ===== Backend Languages & Frameworks =====
        TechSignature {
            name: "PHP",
            category: "Programming Language",
            website: Some("https://www.php.net"),
            cpe: Some("cpe:2.3:a:php:php"),
            patterns: vec![
                SignaturePattern::Header { key: "x-powered-by", regex: r"PHP(?:/([\d.]+))?", confidence: 90, version_group: Some(1) },
                SignaturePattern::Cookie { name: "PHPSESSID", confidence: 85 },
            ],
        },
        TechSignature {
            name: "ASP.NET",
            category: "Web Framework",
            website: Some("https://dotnet.microsoft.com/apps/aspnet"),
            cpe: Some("cpe:2.3:a:microsoft:asp.net"),
            patterns: vec![
                SignaturePattern::Header { key: "x-powered-by", regex: r"ASP\.NET", confidence: 95, version_group: None },
                SignaturePattern::Header { key: "x-aspnet-version", regex: r"([\d.]+)", confidence: 95, version_group: Some(1) },
                SignaturePattern::Cookie { name: "ASP.NET_SessionId", confidence: 90 },
            ],
        },
        TechSignature {
            name: "Node.js",
            category: "Runtime",
            website: Some("https://nodejs.org"),
            cpe: Some("cpe:2.3:a:nodejs:node.js"),
            patterns: vec![
                SignaturePattern::Header { key: "x-powered-by", regex: r"Node\.js", confidence: 85, version_group: None },
            ],
        },
        TechSignature {
            name: "Express",
            category: "Web Framework",
            website: Some("https://expressjs.com"),
            cpe: Some("cpe:2.3:a:expressjs:express"),
            patterns: vec![
                SignaturePattern::Header { key: "x-powered-by", regex: r"Express", confidence: 90, version_group: None },
            ],
        },
        TechSignature {
            name: "Python",
            category: "Programming Language",
            website: Some("https://www.python.org"),
            cpe: Some("cpe:2.3:a:python:python"),
            patterns: vec![
                SignaturePattern::Header { key: "server", regex: r"Python/([\d.]+)", confidence: 80, version_group: Some(1) },
            ],
        },
        TechSignature {
            name: "Django",
            category: "Web Framework",
            website: Some("https://www.djangoproject.com"),
            cpe: Some("cpe:2.3:a:djangoproject:django"),
            patterns: vec![
                SignaturePattern::Cookie { name: "csrftoken", confidence: 75 },
                SignaturePattern::Cookie { name: "sessionid", confidence: 70 },
                SignaturePattern::HtmlContent { regex: r"csrfmiddlewaretoken", confidence: 80, version_group: None },
            ],
        },
        TechSignature {
            name: "Flask",
            category: "Web Framework",
            website: Some("https://flask.palletsprojects.com"),
            cpe: Some("cpe:2.3:a:palletsprojects:flask"),
            patterns: vec![
                SignaturePattern::Cookie { name: "session", confidence: 70 },
                SignaturePattern::Header { key: "server", regex: r"Werkzeug", confidence: 75, version_group: None },
            ],
        },
        TechSignature {
            name: "Ruby",
            category: "Programming Language",
            website: Some("https://www.ruby-lang.org"),
            cpe: Some("cpe:2.3:a:ruby-lang:ruby"),
            patterns: vec![
                SignaturePattern::Header { key: "x-powered-by", regex: r"Ruby", confidence: 80, version_group: None },
            ],
        },
        TechSignature {
            name: "Rails",
            category: "Web Framework",
            website: Some("https://rubyonrails.org"),
            cpe: Some("cpe:2.3:a:rubyonrails:rails"),
            patterns: vec![
                SignaturePattern::Cookie { name: "_session_id", confidence: 75 },
                SignaturePattern::HtmlMeta { name: "csrf-token", content_regex: r".*", confidence: 80, version_group: None },
            ],
        },

        // ===== CDN & Cloud Providers =====
        TechSignature {
            name: "Cloudflare",
            category: "CDN",
            website: Some("https://www.cloudflare.com"),
            cpe: None,
            patterns: vec![
                SignaturePattern::Header { key: "server", regex: r"cloudflare", confidence: 95, version_group: None },
                SignaturePattern::Header { key: "cf-ray", regex: r".*", confidence: 95, version_group: None },
                SignaturePattern::Cookie { name: "__cflb", confidence: 85 },
            ],
        },
        TechSignature {
            name: "Amazon CloudFront",
            category: "CDN",
            website: Some("https://aws.amazon.com/cloudfront"),
            cpe: None,
            patterns: vec![
                SignaturePattern::Header { key: "x-amz-cf-id", regex: r".*", confidence: 95, version_group: None },
                SignaturePattern::Header { key: "via", regex: r"cloudfront", confidence: 90, version_group: None },
            ],
        },

        // ===== Operating Systems =====
        TechSignature {
            name: "Ubuntu",
            category: "Operating System",
            website: Some("https://ubuntu.com"),
            cpe: Some("cpe:2.3:o:canonical:ubuntu_linux"),
            patterns: vec![
                SignaturePattern::Header { key: "server", regex: r"Ubuntu", confidence: 90, version_group: None },
                SignaturePattern::Header { key: "x-powered-by", regex: r"Ubuntu", confidence: 90, version_group: None },
            ],
        },
        TechSignature {
            name: "CentOS",
            category: "Operating System",
            website: Some("https://www.centos.org"),
            cpe: Some("cpe:2.3:o:centos:centos"),
            patterns: vec![
                SignaturePattern::Header { key: "server", regex: r"CentOS", confidence: 90, version_group: None },
                SignaturePattern::Header { key: "x-powered-by", regex: r"CentOS", confidence: 90, version_group: None },
            ],
        },
        TechSignature {
            name: "Debian",
            category: "Operating System",
            website: Some("https://www.debian.org"),
            cpe: Some("cpe:2.3:o:debian:debian_linux"),
            patterns: vec![
                SignaturePattern::Header { key: "server", regex: r"Debian", confidence: 90, version_group: None },
            ],
        },
        TechSignature {
            name: "Windows Server",
            category: "Operating System",
            website: Some("https://www.microsoft.com/windowsserver"),
            cpe: Some("cpe:2.3:o:microsoft:windows_server"),
            patterns: vec![
                SignaturePattern::Header { key: "server", regex: r"Microsoft-HTTPAPI", confidence: 85, version_group: None },
                SignaturePattern::Header { key: "server", regex: r"Microsoft-IIS", confidence: 85, version_group: None },
            ],
        },
        // ===== CI/CD & DevOps =====
        TechSignature {
            name: "Jenkins",
            category: "CI/CD",
            website: Some("https://www.jenkins.io"),
            cpe: Some("cpe:2.3:a:jenkins:jenkins"),
            patterns: vec![
                SignaturePattern::Header { key: "x-jenkins", regex: r"([\d.]+)", confidence: 100, version_group: Some(1) },
                SignaturePattern::Header { key: "x-hudson", regex: r".*", confidence: 90, version_group: None },
                SignaturePattern::HtmlContent { regex: r"Jenkins", confidence: 80, version_group: None },
                // Common Jenkins Favicon MD5
                SignaturePattern::Favicon { hash: "c018c160e4c6e40938f3235775f0a35e", confidence: 100 },
            ],
        },
        TechSignature {
            name: "GitLab",
            category: "CI/CD",
            website: Some("https://about.gitlab.com"),
            cpe: Some("cpe:2.3:a:gitlab:gitlab"),
            patterns: vec![
                SignaturePattern::Cookie { name: "_gitlab_session", confidence: 100 },
                SignaturePattern::HtmlContent { regex: r"gon\.gitlab_url", confidence: 95, version_group: None },
            ],
        },
        TechSignature {
            name: "Grafana",
            category: "Monitoring",
            website: Some("https://grafana.com"),
            cpe: Some("cpe:2.3:a:grafana:grafana"),
            patterns: vec![
                SignaturePattern::Cookie { name: "grafana_session", confidence: 100 },
                SignaturePattern::HtmlContent { regex: r"Grafana", confidence: 85, version_group: None },
                SignaturePattern::HtmlContent { regex: r"window\.grafanaBootData", confidence: 95, version_group: None },
            ],
        },
        TechSignature {
            name: "Prometheus",
            category: "Monitoring",
            website: Some("https://prometheus.io"),
            cpe: Some("cpe:2.3:a:prometheus:prometheus"),
            patterns: vec![
                SignaturePattern::HtmlContent { regex: r"Prometheus Time Series Collection and Processing Server", confidence: 95, version_group: None },
            ],
        },
        TechSignature {
            name: "Kibana",
            category: "Monitoring",
            website: Some("https://www.elastic.co/kibana"),
            cpe: Some("cpe:2.3:a:elasticsearch:kibana"),
            patterns: vec![
                SignaturePattern::Header { key: "kbn-name", regex: r"kibana", confidence: 100, version_group: None },
                SignaturePattern::Header { key: "kbn-version", regex: r"([\d.]+)", confidence: 100, version_group: Some(1) },
                SignaturePattern::HtmlContent { regex: r"kibana", confidence: 80, version_group: None },
            ],
        },

        // ===== Enterprise Applications =====
        TechSignature {
            name: "Jira",
            category: "Issue Tracker",
            website: Some("https://www.atlassian.com/software/jira"),
            cpe: Some("cpe:2.3:a:atlassian:jira"),
            patterns: vec![
                SignaturePattern::Header { key: "x-arequestid", regex: r".*", confidence: 90, version_group: None },
                SignaturePattern::Header { key: "x-ausername", regex: r".*", confidence: 90, version_group: None },
                SignaturePattern::HtmlMeta { name: "application-name", content_regex: r"JIRA", confidence: 95, version_group: None },
            ],
        },
        TechSignature {
            name: "Confluence",
            category: "Wiki",
            website: Some("https://www.atlassian.com/software/confluence"),
            cpe: Some("cpe:2.3:a:atlassian:confluence"),
            patterns: vec![
                SignaturePattern::Header { key: "x-confluence-request-time", regex: r".*", confidence: 95, version_group: None },
                SignaturePattern::HtmlMeta { name: "confluence-request-time", content_regex: r".*", confidence: 95, version_group: None },
            ],
        },
        TechSignature {
            name: "Oracle WebLogic",
            category: "Application Server",
            website: Some("https://www.oracle.com/middleware/technologies/weblogic.html"),
            cpe: Some("cpe:2.3:a:oracle:weblogic_server"),
            patterns: vec![
                SignaturePattern::Header { key: "x-oracle-dms-ecid", regex: r".*", confidence: 90, version_group: None },
                SignaturePattern::Header { key: "x-powered-by", regex: r"Servlet/.*", confidence: 80, version_group: None },
            ],
        },
        TechSignature {
            name: "SAP NetWeaver",
            category: "Application Server",
            website: Some("https://www.sap.com"),
            cpe: Some("cpe:2.3:a:sap:netweaver"),
            patterns: vec![
                SignaturePattern::Cookie { name: "sap-usercontext", confidence: 95 },
                SignaturePattern::Header { key: "server", regex: r"SAP NetWeaver Application Server", confidence: 100, version_group: None },
            ],
        },
        TechSignature {
            name: "Salesforce",
            category: "CRM",
            website: Some("https://www.salesforce.com"),
            cpe: None,
            patterns: vec![
                SignaturePattern::Cookie { name: "sid", confidence: 60 }, // Generic but combined with others
                SignaturePattern::Header { key: "server", regex: r"force\.com", confidence: 95, version_group: None },
            ],
        },

        // ===== Security Devices =====
        TechSignature {
            name: "Fortinet",
            category: "Firewall",
            website: Some("https://www.fortinet.com"),
            cpe: Some("cpe:2.3:h:fortinet:fortigate"),
            patterns: vec![
                SignaturePattern::Cookie { name: "APSCOOKIE", confidence: 90 },
                SignaturePattern::HtmlContent { regex: r"FortiGate", confidence: 90, version_group: None },
                SignaturePattern::Header { key: "server", regex: r"xps", confidence: 80, version_group: None },
            ],
        },
        TechSignature {
            name: "Palo Alto Networks",
            category: "Firewall",
            website: Some("https://www.paloaltonetworks.com"),
            cpe: Some("cpe:2.3:h:paloaltonetworks:pa-series"),
            patterns: vec![
                SignaturePattern::HtmlContent { regex: r"GlobalProtect", confidence: 95, version_group: None },
            ],
        },
        TechSignature {
            name: "Citrix NetScaler",
            category: "Load Balancer",
            website: Some("https://www.citrix.com"),
            cpe: Some("cpe:2.3:a:citrix:netscaler"),
            patterns: vec![
                SignaturePattern::Cookie { name: "ns_af", confidence: 90 },
                SignaturePattern::Cookie { name: "citrix_ns_id", confidence: 90 },
                SignaturePattern::Header { key: "via", regex: r"NS-CACHE", confidence: 90, version_group: None },
            ],
        },
        TechSignature {
            name: "BigIP",
            category: "Load Balancer",
            website: Some("https://www.f5.com"),
            cpe: Some("cpe:2.3:a:f5:big-ip"),
            patterns: vec![
                SignaturePattern::Cookie { name: "BigIP", confidence: 95 },
                SignaturePattern::Cookie { name: "BIGipServer", confidence: 95 },
            ],
        },

        // ===== Container & Orchestration (K8s ilk-temas tespiti) =====
        // Türkçe: K8s apiserver/Rancher HTTP üstünden damgalanır — 401/403 Status JSON'u
        // bile K8s kanıtıdır ("kind":"Status" + apiVersion). Bu imzalar recon'un
        // technologies çıktısına düşer → orchestrator attack_graph "k8s-control-plane"
        // kategorisiyle eşleştirir.
        TechSignature {
            name: "Kubernetes",
            category: "Orchestration",
            website: Some("https://kubernetes.io"),
            cpe: Some("cpe:2.3:a:kubernetes:kubernetes"),
            patterns: vec![
                SignaturePattern::Header { key: "server", regex: r"kubernetes", confidence: 95, version_group: None },
                SignaturePattern::HtmlContent { regex: r#""kind":"Status","apiVersion":"v1""#, confidence: 90, version_group: None },
                SignaturePattern::HtmlContent { regex: r#""gitVersion":"v[0-9]+\.[0-9]+\.[0-9]+"#, confidence: 85, version_group: None },
            ],
        },
        TechSignature {
            name: "Rancher",
            category: "Orchestration",
            website: Some("https://rancher.com"),
            cpe: Some("cpe:2.3:a:rancher:rancher"),
            patterns: vec![
                SignaturePattern::HtmlContent { regex: r"<title>Rancher</title>", confidence: 95, version_group: None },
                // Norman API imzası (Rancher'ın API framework'ü — ayırt edici)
                SignaturePattern::HtmlContent { regex: r#""baseType":"(error|collection)""#, confidence: 80, version_group: None },
            ],
        },
        TechSignature {
            name: "RKE2",
            category: "Orchestration",
            website: Some("https://docs.rke2.io"),
            cpe: None,
            patterns: vec![
                // gitVersion suffix dağıtımı damgalar: v1.28.4+rke2r1
                SignaturePattern::HtmlContent { regex: r#""gitVersion":"v[0-9.]+\+rke2r[0-9]+"#, confidence: 95, version_group: None },
            ],
        },
        TechSignature {
            name: "K3s",
            category: "Orchestration",
            website: Some("https://k3s.io"),
            cpe: None,
            patterns: vec![
                SignaturePattern::HtmlContent { regex: r#""gitVersion":"v[0-9.]+\+k3s[0-9]+"#, confidence: 95, version_group: None },
            ],
        },
        TechSignature {
            name: "Docker",
            category: "Container",
            website: Some("https://www.docker.com"),
            cpe: Some("cpe:2.3:a:docker:docker"),
            patterns: vec![
                SignaturePattern::Header { key: "server", regex: r"Docker", confidence: 90, version_group: None },
            ],
        },
    ]
});

/// Teknoloji tespiti ana fonksiyonu - HTTP response üzerinden pattern matching
pub fn detect_technologies(
    html: &str,
    headers: &HashMap<String, String>,
    cookies: &HashMap<String, String>,
    favicon_hash: Option<&str>,
) -> Vec<Technology> {
    let mut detected = Vec::new();
    let document = Html::parse_document(html);

    // Her signature için kontrol yap
    for signature in TECH_SIGNATURES.iter() {
        let mut max_confidence = 0u8;
        let mut detected_version: Option<String> = None;

        for pattern in &signature.patterns {
            match pattern {
                // HTTP Header kontrolü (version extraction destekli)
                SignaturePattern::Header { key, regex, confidence, version_group } => {
                    if let Some(value) = headers.get(&key.to_lowercase()) {
                        if let Ok(re) = Regex::new(regex) {
                            if let Some(captures) = re.captures(value) {
                                max_confidence = max_confidence.max(*confidence);
                                if let Some(group_idx) = version_group {
                                    if let Some(version_match) = captures.get(*group_idx) {
                                        detected_version = Some(version_match.as_str().to_string());
                                    }
                                }
                            }
                        }
                    }
                }

                // HTML Meta tag kontrolü
                SignaturePattern::HtmlMeta { name, content_regex, confidence, version_group } => {
                    let selector = Selector::parse(&format!(r#"meta[name="{}"]"#, name))
                        .unwrap_or_else(|_| Selector::parse("meta").unwrap());
                    
                    for element in document.select(&selector) {
                        if let Some(content) = element.value().attr("content") {
                            if let Ok(re) = Regex::new(content_regex) {
                                if let Some(captures) = re.captures(content) {
                                    max_confidence = max_confidence.max(*confidence);
                                    if let Some(group_idx) = version_group {
                                        if let Some(version_match) = captures.get(*group_idx) {
                                            detected_version = Some(version_match.as_str().to_string());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // Script src URL pattern kontrolü
                SignaturePattern::ScriptSrc { regex, confidence, version_group } => {
                    let selector = Selector::parse("script[src]").unwrap();
                    for element in document.select(&selector) {
                        if let Some(src) = element.value().attr("src") {
                            if let Ok(re) = Regex::new(regex) {
                                if let Some(captures) = re.captures(src) {
                                    max_confidence = max_confidence.max(*confidence);
                                    if let Some(group_idx) = version_group {
                                        if let Some(version_match) = captures.get(*group_idx) {
                                            detected_version = Some(version_match.as_str().to_string());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // Cookie kontrolü
                SignaturePattern::Cookie { name, confidence } => {
                    if cookies.contains_key(*name) {
                        max_confidence = max_confidence.max(*confidence);
                    }
                }

                // HTML içerik pattern matching
                SignaturePattern::HtmlContent { regex, confidence, version_group } => {
                    if let Ok(re) = Regex::new(regex) {
                        if let Some(captures) = re.captures(html) {
                            max_confidence = max_confidence.max(*confidence);
                            if let Some(group_idx) = version_group {
                                if let Some(version_match) = captures.get(*group_idx) {
                                    detected_version = Some(version_match.as_str().to_string());
                                }
                            }
                        }
                    }
                }

                // Link href pattern kontrolü (CSS, favicon vb.)
                SignaturePattern::LinkHref { regex, confidence, version_group } => {
                    let selector = Selector::parse("link[href]").unwrap();
                    for element in document.select(&selector) {
                        if let Some(href) = element.value().attr("href") {
                            if let Ok(re) = Regex::new(regex) {
                                if let Some(captures) = re.captures(href) {
                                    max_confidence = max_confidence.max(*confidence);
                                    if let Some(group_idx) = version_group {
                                        if let Some(version_match) = captures.get(*group_idx) {
                                            detected_version = Some(version_match.as_str().to_string());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // Favicon hash kontrolü (MD5)
                SignaturePattern::Favicon { hash, confidence } => {
                    if let Some(f_hash) = favicon_hash {
                        if f_hash == *hash {
                            max_confidence = max_confidence.max(*confidence);
                        }
                    }
                }
            }
        }

        // Tespit eşiği: %60 ve üzeri confidence
        if max_confidence >= 60 {
            detected.push(Technology {
                name: signature.name.to_string(),
                version: detected_version,
                category: signature.category.to_string(),
                confidence: max_confidence,
                website: signature.website.map(|s| s.to_string()),
                cpe: signature.cpe.map(|s| s.to_string()),
            });
        }
    }

    detected
}
