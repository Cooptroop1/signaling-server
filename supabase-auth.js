// Complete Supabase auth helper file
console.log('Supabase auth helper loaded');
const SUPABASE_URL = 'https://crgmcdpmmxtrcocfbsac.supabase.co';
const SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImNyZ21jZHBtbXh0cmNvY2Zic2FjIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzM2NjI4NTksImV4cCI6MjA4OTIzODg1OX0.pgEIhCIRKEjmwgIQVeQtXdzIWZu2diPXr-gjpvV7pGs';
window.supabaseClient = supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY);