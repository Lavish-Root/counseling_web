// Detailed data from reference image (Preserve Exact Order)
export const featuredColleges = [
    "Anantha Laxmi Government Ayurvedic Medical College (ALGAMC), Warangal, Telangana",
    "Government Ayurved College, Rewa, Madhya Pradesh",
    "Aarupadai Veedu Medical College, Pondicherry",
    "ACS Medical College and Hospital, Chennai",
    "Agartala Government Dental College",
    "Agartala Government Medical College,Agartala",
    "Agenugrah Narayan Magadh Medical Colle, Gaya",
    "AIIMS Bathinda, (All India Institute of Medical Science , Bathinda)",
    "AIIMS Nagpur -All India Institute of Medical Science, Nagpur",
    "Aligarh Muslim University, AMU",
    "Aligarh Muslim, University",
    "All India Institute of Ayurveda, North Goa, Goa",
    "All India Institute of Medical Sciences, Bhubaneswar"
];

// Other colleges
export const otherColleges = [
    "AIIMS Deoghar", "AIIMS Kalyani", "AIIMS New Delhi", "AIIMS Patna",
    "GMC Amritsar", "GMC Aurangabad", "GMC Akola", "GMC Alibag", "GMC Anantnag", "GMC Ariyalur", "GMC Bahraich",
    "GMC Baramulla", "GMC Barmer", "GMC Bharatpur", "GMC Bhavnagar", "GMC Bhilwara", "GMC Bundi", "GMC Chandrapur",
    "GMC Chhindwara", "GMC Chittorgarh", "GMC Churu", "GMC Datia", "GMC Dausa", "GMC Dholpur", "GMC Doda", "GMC Dungarpur",
    "GMC Ernakulam", "GMC Firozabad", "GMC Gondia", "GMC Hamirpur", "GMC Handwara", "GMC Idukki", "GMC Jalgaon",
    "GMC Jammu", "GMC Kannauj", "GMC Karauli", "GMC Karur", "GMC Kathua", "GMC Khandwa", "GMC Kollam", "GMC Konni",
    "GMC Kota", "GMC Kottayam",
    "GDC Agartala", "GDC Kottayam", "GDC Indore", "GDC Ahmedabad", "GDC Amritsar", "GDC Aurangabad", "GDC Jamnagar",
    "GDC Mumbai", "GDC Nagpur", "GDC Nalanda", "GDC Patiala", "GDC Pudukottai", "GDC Shimla", "GDC Srinagar",
    "Ashtang Ayurved Mahavidyalaya (Pune)", "Ayurved Seva Sangh's Ayurved Mahavidyalaya (Nashik)",
    "Ayurvedic and Unani Tibbia College (Delhi)",
    "Banaras Hindu University (BHU)", "Delhi university", "Amity University",
    "Bangalore Medical College",
    "CMC Vellore", "KGMU Lucknow", "MAMC New Delhi", "AFMC Pune", "JIPMER Puducherry",
    "Bihar Veterinary College, Patna",
    "BPS Government Medical College for Women, Sonepat",
    "BRD Medical College, Gorakhpur",
    "Bundelkhand Government Ayurvedic College and Hospital, Jhansi",
    "Bundelkhand Medical College, Sagar",
    "Burdwan Dental College and Hospital",
    "Calcutta National Medical College, Kolkata",
    "Ch. Brahm Prakash Ayurved, Najafgarh, New Delhi",
    "Chamrajanagar Institute of Medical Sciences, Karnataka",
    "Chengalpattu Medical College, Chengalpattu",
    "Chettinad Hospital & Research Institute, Kanchipuram",
    "Chikkaballapura Institute of Medical Sciences"
];

// Combine: Featured first (order preserved), then others sorted
export const collegesData = [
    ...featuredColleges,
    ...[...new Set(otherColleges)].sort()
];
