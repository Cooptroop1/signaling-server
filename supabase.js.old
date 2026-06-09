// supabase.js
const SUPABASE_URL = 'https://crgmcdpmmxtrcocfbsac.supabase.co';
const SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImNyZ21jZHBtbXh0cmNvY2Zic2FjIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzM2NjI4NTksImV4cCI6MjA4OTIzODg1OX0.pgEIhCIRKEjmwgIQVeQtXdzIWZu2diPXr-gjpvV7pGs';

const supabase = window.supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

// Check if a profile with this display_name already exists
async function checkProfileExists(displayName) {
    const { data, error } = await supabase
        .from('profiles')
        .select('id')
        .eq('display_name', displayName)
        .single();

    if (error && error.code !== 'PGRST116') {
        console.error('Error checking profile:', error);
        return false;
    }
    return !!data;
}

// Create a new profile
async function createProfile(displayName) {
    const { data, error } = await supabase
        .from('profiles')
        .insert([{ display_name: displayName }])
        .select()
        .single();

    if (error) {
        console.error('Error creating profile:', error);
        throw error;
    }
    return data;
}

// Make functions available globally
window.checkProfileExists = checkProfileExists;
window.createProfile = createProfile;
