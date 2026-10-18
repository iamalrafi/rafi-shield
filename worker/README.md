# রিপোর্ট সার্ভিস (Cloudflare Workers, ফ্রি)

অ্যাপ থেকে আসা রিপোর্ট জমা রাখে, সাধারণ রেট-লিমিট ও ডুপ্লিকেট চেক করে, আর আপনি (রিভিউয়ার) ওয়েব পেজ থেকে অনুমোদন বা প্রত্যাখ্যান করতে পারেন।

## ধাপ

1. https://dash.cloudflare.com এ ফ্রি অ্যাকাউন্ট খুলুন।
2. **Storage & Databases → KV → Create a namespace**। নাম দিন `betting-shield-reports`।
3. **Workers & Pages → Create → Create Worker** (Hello World)। নাম দিন `betting-shield`। **Deploy** চাপুন, তারপর **Edit code**।
4. এডিটরের সব লেখা মুছে এই ফোল্ডারের `index.js` ফাইলের পুরো লেখা পেস্ট করুন। **Deploy** চাপুন।
5. Worker-এর **Settings → Bindings → Add → KV namespace**: Variable name = `REPORTS`, namespace = `betting-shield-reports`।
6. **Settings → Variables and Secrets → Add**:
   - `ADMIN_TOKEN` (Type: **Secret**): কমপক্ষে ২০ অক্ষরের একটি লম্বা গোপন পাসওয়ার্ড। এটি দিয়ে আপনি রিভিউ পেজে ঢুকবেন।
   - `LIST_URL` (Type: Text): `https://raw.githubusercontent.com/আপনার_GITHUB_নাম/betting-shield-bd/main/blocklist/blocklist.txt` (এতে "আগেই তালিকায় আছে" শনাক্ত হয়)।
7. Worker-এর ঠিকানা (যেমন `https://betting-shield.xxxx.workers.dev`) কপি করুন এবং GitHub রিপোজিটরির `REPORT_ENDPOINT` ভেরিয়েবলে বসান (প্রধান README ধাপ ৫)। শেষে `/` দেবেন না।

## রিভিউ করার নিয়ম

1. ব্রাউজারে `আপনার-worker-ঠিকানা/admin` খুলুন, **Enter admin token** চেপে ADMIN_TOKEN দিন।
2. প্রতিটি রিপোর্টের সাইট নিজে দেখে নিশ্চিত হোন এটি সত্যিই বেটিং কি না, তারপর **approved** বা **rejected** চাপুন। কাজ চলার সময় **under_review** দিতে পারেন।
3. **Export approved domains** চাপলে দুটি তালিকা পাবেন। প্রথমটি GitHub-এর `blocklist/manual.txt` এ এবং দ্বিতীয়টি (ভুল ব্লক সংশোধন) `blocklist/allow.txt` এ যোগ করে Commit করুন। তালিকা স্বয়ংক্রিয়ভাবে সাইন হয়ে সবার কাছে পৌঁছাবে।

কেউ জোর করে কোনো সাইট ব্লক করাতে পারে না: রিপোর্ট শুধু আপনার অনুমোদনের পরই তালিকায় যায়।

## গোপনীয়তা

সার্ভিস রিপোর্ট নম্বর, ডোমেইন, নোট ও সময় রাখে। আইপি ঠিকানা সংরক্ষণ করা হয় না (রেট-লিমিটের জন্য শুধু এক ঘণ্টার একটি হ্যাশ থাকে)।
