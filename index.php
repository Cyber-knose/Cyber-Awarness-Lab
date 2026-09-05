<?php
declare(strict_types=1);
?>

<!DOCTYPE html>
<html lang="en">

<head>

<meta charset="UTF-8">

<meta name="viewport"
content="width=device-width, initial-scale=1.0">

<title>Cyber Abhiyan | NextGen Securities</title>

<script src="https://cdn.tailwindcss.com"></script>

<link
href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap"
rel="stylesheet">

<style>

*{
margin:0;
padding:0;
box-sizing:border-box;
}

body{
font-family:'Inter',sans-serif;
background:#010409;
color:white;
overflow-x:hidden;
}

.hero{

background:
radial-gradient(circle at 15% 20%,rgba(0,255,170,.16),transparent 28%),
radial-gradient(circle at 80% 15%,rgba(0,200,255,.18),transparent 30%),
radial-gradient(circle at 50% 100%,rgba(0,255,100,.10),transparent 35%),
linear-gradient(180deg,#000000,#020617,#000000);

}

.glass{

background:rgba(8,15,30,.60);
backdrop-filter:blur(18px);
border:1px solid rgba(0,255,170,.12);

box-shadow:
0 0 25px rgba(0,255,170,.04),
inset 0 0 8px rgba(255,255,255,.02);

transition:.35s;

}

.glass:hover{

transform:translateY(-8px);

border-color:#00ffd0;

box-shadow:

0 0 20px rgba(0,255,170,.30),

0 0 60px rgba(0,255,170,.12),

0 0 120px rgba(0,255,170,.05);

}

.titleGlow{

text-shadow:

0 0 10px rgba(0,255,170,.8),

0 0 25px rgba(0,255,170,.6),

0 0 45px rgba(0,255,170,.3);

}

.btn{

transition:.3s;

}

.btn:hover{

transform:translateY(-3px);

box-shadow:0 0 30px rgba(0,255,170,.40);

}

.stats{

background:linear-gradient(90deg,#052e16,#042f2e);

}

</style>

</head>

<body>

<section class="hero min-h-screen">

<div class="max-w-7xl mx-auto px-6 py-16">

<div class="text-center">

<span class="inline-flex items-center px-6 py-3 rounded-full border border-green-400/40 bg-green-500/10 text-green-300 font-semibold">

🛡️ NEXTGEN SECURITIES

</span>

<h1 class="mt-10 text-6xl md:text-8xl font-black">
<span class="text-neon-400 titleGlow">

Cyber

<span class="text-neon-400 titleGlow">

Abhiyan

</span>

</h1>

<p class="mt-8 max-w-3xl mx-auto text-slate-300 text-xl leading-9">

Professional browser-based cybersecurity tools built by

<strong class="text-green-400">

NextGen Securities

</strong>

for Students, Ethical Hackers, Developers, Security Researchers and Organizations.

</p>

<div class="mt-12 flex justify-center gap-6 flex-wrap">


<a href="#tools"

class="btn px-8 py-4 rounded-xl border border-green-500 text-green-400">

Explore Tools

</a>

</div>

</div>

<div id="tools" class="grid md:grid-cols-2 xl:grid-cols-3 gap-8 mt-24">
    
<!-- ============================= -->
<!-- Metadata Purifier Card -->
<!-- ============================= -->

<a href="metadata/">

<div class="glass rounded-3xl p-10 h-full">

<div
class="w-20 h-20 rounded-2xl
bg-green-500/20
flex items-center justify-center
text-5xl">

🧹

</div>

<h2 class="text-3xl font-bold mt-8">

Metadata Purifier

</h2>

<p class="mt-5 text-slate-400 leading-8">

Remove hidden EXIF metadata from your images before sharing them online.
Protect your privacy by deleting GPS coordinates, camera information and
other sensitive metadata in seconds.

</p>

<ul class="mt-6 space-y-2 text-green-300">

<li>✔ Remove EXIF Data</li>

<li>✔ Privacy Protection</li>

<li>✔ Browser Based</li>

<li>✔ Free Forever</li>

</ul>

<div class="mt-8 text-green-400 font-semibold">

Launch Tool →

</div>

</div>

</a>





<!-- ============================= -->
<!-- Cyber Kavach Card -->
<!-- ============================= -->

<a href="kavach/">

<div class="glass rounded-3xl p-10 h-full">

<div
class="w-20 h-20 rounded-2xl
bg-cyan-500/20
flex items-center justify-center
text-5xl">

🛡️

</div>

<h2 class="text-3xl font-bold mt-8">

Cyber Kavach

</h2>

<p class="mt-5 text-slate-400 leading-8">

A professional Password Security Laboratory that analyzes password strength
using advanced security metrics, attack simulations, and modern
cryptographic techniques. Designed for developers, cybersecurity students, and
security professionals.

</p>

<ul class="mt-6 space-y-2 text-cyan-300">

<li>✔ Secure Password Generator</li>

<li>✔ Password Mutation Analyzer</li>

<li>✔ Breach Exposure Simulator</li>

<li>✔ Password History Comparison</li>

</ul>

<div class="mt-8 text-cyan-400 font-semibold">

Open Cyber Kavach →

</div>

</div>

</a>





<!-- ============================= -->
<!-- Cyber-Yantra Card -->
<!-- ============================= -->

<a href="Cyber-Yantra/">

<div class="glass rounded-3xl p-10 h-full">

<div
class="w-20 h-20 rounded-2xl
bg-purple-500/20
flex items-center justify-center
text-5xl">

⚡

</div>

<h2 class="text-3xl font-bold mt-8">

Cyber-Yantra

</h2>

<p class="mt-5 text-slate-400 leading-8">

A professional collection of cybersecurity utilities designed for
ethical hackers, developers, bug bounty hunters and students.

</p>

<ul class="mt-6 space-y-2 text-purple-300">

<li>✔ Hash Generator</li>

<li>✔ Hash Identifier</li>

<li>✔ File Hash Checker</li>

<li>✔ Base64 Encoder/Decoder</li>

<li>✔ URL Encoder/Decoder</li>

<li>✔ Timestamp Converter</li>

<li>✔ Random Data Generator</li>

<li>✔ UUID Generator</li>

</ul>

<div class="mt-8 text-purple-400 font-semibold">

Launch Cyber-Yantra →

</div>

</div>

</a>





<!-- ============================= -->
<!-- Cyber Awareness Lab Card -->
<!-- ============================= -->

<a href="cyber-awarness/">

<div class="glass rounded-3xl p-10 h-full">

<div
class="w-20 h-20 rounded-2xl
bg-yellow-500/20
flex items-center justify-center
text-5xl">

🔬

</div>

<h2 class="text-3xl font-bold mt-8">

Cyber Awareness Lab

</h2>

<p class="mt-5 text-slate-400 leading-8">

An interactive cybersecurity awareness platform with 14 educational modules
covering ransomware, trojans, worms, spyware, keyloggers, rootkits, adware,
fileless malware, botnets, cryptojacking, SOC analysis, social engineering,
and AI-powered modern threats.

</p>

<ul class="mt-6 space-y-2 text-yellow-300">

<li>✔ 14 Interactive Modules</li>

<li>✔ Malware Behavior Demos</li>

<li>✔ Social Engineering Labs</li>

<li>✔ AI Threat Simulations</li>

<li>✔ Browser Based & Safe</li>

</ul>

<div class="mt-8 text-yellow-400 font-semibold">

Enter Lab →

</div>

</div>

</a>

</div>





<!-- ============================= -->
<!-- Statistics -->
<!-- ============================= -->

<div class="mt-24">

<div class="stats rounded-3xl p-12">

<div class="grid md:grid-cols-4 gap-10 text-center">

<div>

<div class="text-5xl font-black text-green-400">

Open Source

</div>

<p class="mt-3 text-slate-300">

Cybersecurity Tools

</p>

</div>

<div>

<div class="text-5xl font-black text-cyan-400">

100%

</div>

<p class="mt-3 text-slate-300">

Browser Based

</p>

</div>

<div>

<div class="text-5xl font-black text-purple-400">

Free

</div>

<p class="mt-3 text-slate-300">

No Registration

</p>

</div>

<div>

<div class="text-5xl font-black text-emerald-400">

24×7

</div>

<p class="mt-3 text-slate-300">

Available Anytime

</p>

</div>

</div>

</div>

</div>

<!-- ============================= -->
<!-- Why Cyber Abhiyan -->
<!-- ============================= -->

<div class="mt-28">

<div class="text-center max-w-5xl mx-auto">

<span class="inline-block px-5 py-2 rounded-full bg-green-500/10 border border-green-500/30 text-green-300 font-semibold">
WHY TO CHOOSE US

</span>

<h2 class="mt-8 text-5xl font-extrabold">

Why Choose

<span class="text-neon-400 titleGlow">

Cyber Abhiyan?

</span>

</h2>

<p class="mt-8 text-slate-400 text-xl leading-10">

Cyber Abhiyan is a growing ecosystem of browser-based cybersecurity tools
developed by <span class="text-green-400 font-semibold">NextGen Securities</span>.
Our mission is to make professional security utilities accessible to
students, developers, ethical hackers, bug bounty hunters and organizations
without requiring software installation.

</p>

</div>

</div>





<!-- ============================= -->
<!-- Features -->
<!-- ============================= -->

<div class="grid md:grid-cols-2 xl:grid-cols-4 gap-8 mt-20">

<div class="glass rounded-3xl p-8">

<div class="text-5xl">

⚡

</div>

<h3 class="mt-6 text-2xl font-bold">

Lightning Fast

</h3>

<p class="mt-4 text-slate-400 leading-8">

Every tool runs instantly inside your browser with no installation required.

</p>

</div>





<div class="glass rounded-3xl p-8">

<div class="text-5xl">

🔒

</div>

<h3 class="mt-6 text-2xl font-bold">

Privacy First

</h3>

<p class="mt-4 text-slate-400 leading-8">

Your files stay on your device whenever possible, ensuring maximum privacy.

</p>

</div>





<div class="glass rounded-3xl p-8">

<div class="text-5xl">

💻

</div>

<h3 class="mt-6 text-2xl font-bold">

Professional Tools

</h3>

<p class="mt-4 text-slate-400 leading-8">

Useful utilities for students, penetration testers, developers and security professionals.

</p>

</div>





<div class="glass rounded-3xl p-8">

<div class="text-5xl">

🚀

</div>

<h3 class="mt-6 text-2xl font-bold">

Always Growing

</h3>

<p class="mt-4 text-slate-400 leading-8">

New cybersecurity utilities and learning resources are continuously added.

</p>

</div>

</div>





<!-- ============================= -->
<!-- CTA -->
<!-- ============================= -->

<div class="mt-28">

<div class="rounded-3xl overflow-hidden bg-gradient-to-r from-green-600 via-emerald-600 to-cyan-600 p-14 text-center shadow-2xl">

<h2 class="text-5xl font-black">

Secure Your Digital World

</h2>

<p class="mt-8 text-green-100 text-xl max-w-3xl mx-auto leading-9">

Explore professional browser-based cybersecurity tools designed to simplify
digital security for everyone—from beginners to security experts.

</p>

<div class="mt-12 flex flex-wrap justify-center gap-6">

<a href="kavach/"

class="btn px-8 py-4 rounded-xl bg-black text-green-400 font-bold">

Launch Cyber Kavach

</a>

<a href="Cyber-Yantra/"

class="btn px-8 py-4 rounded-xl bg-white text-black font-bold">

Launch Cyber-Yantra

</a>

<a href="metadata/"

class="btn px-8 py-4 rounded-xl border border-white text-white">

Launch Metadata Purifier

</a>

<a href="cyber-awarness/"

class="btn px-8 py-4 rounded-xl border border-white text-white">

Explore Cyber Awareness Lab

</a>

</div>

</div>

</div>

<!-- ============================= -->
<!-- Footer -->
<!-- ============================= -->

</div>

</section>

<footer class="border-t border-slate-800 bg-black">

<div class="max-w-7xl mx-auto px-6 py-12">

<div class="grid md:grid-cols-3 gap-10">

<!-- Company -->

<div>

<h3 class="text-2xl font-bold text-green-400">

NextGen Securities

</h3>

<p class="mt-5 text-slate-400 leading-8">

Empowering individuals and organizations with modern,
browser-based cybersecurity solutions.

Our mission is to make cybersecurity simple,
accessible and practical for everyone.

</p>

</div>

<!-- Products -->

<div>

<h3 class="text-xl font-semibold text-white">

Products

</h3>

<ul class="mt-5 space-y-3 text-slate-400">

<li>

<a href="kavach/" class="hover:text-neon-400 transition">

🛡️ Cyber Kavach

</a>

</li>

<li>

<a href="Cyber-Yantra/" class="hover:text-neon-400 transition">

⚡ Cyber-Yantra

</a>

</li>

<li>

<a href="metadata/" class="hover:text-neon-400 transition">

🧹 Metadata Purifier

</a>

</li>

<li>

<a href="cyber-awarness/" class="hover:text-neon-400 transition">

🔬 Cyber Awareness Lab

</a>

</li>

</ul>

</div>

<!-- Contact -->

<div>

<h3 class="text-xl font-semibold text-white">

Connect

</h3>

<p class="mt-5 text-slate-400">

Website

</p>

<p class="mt-2 text-green-400">

www.nextgensecurities.in

</p>

<p class="mt-5 text-slate-400">

Email

</p>

<p class="mt-2 text-green-400">

contact@nextgensecurities.in

</p>

</div>

</div>

<div class="border-t border-slate-800 mt-12 pt-8">

<div class="flex flex-col md:flex-row justify-between items-center gap-4">

<p class="text-slate-500 text-center">

© <?php echo date('Y'); ?>
NextGen Securities.
All Rights Reserved.

</p>

<p class="text-slate-500 text-center">

Built with ❤️ for the Cyber Security Community.

</p>

</div>

</div>

</div>

</footer>

</body>

</html>

