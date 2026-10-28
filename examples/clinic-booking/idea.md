# Idea: clinic appointment booking with WhatsApp reminders

## The problem

Sunrise Family Clinic is a small practice with three doctors and two receptionists. Patients book by phone during opening hours, and the receptionists keep the schedule in a shared spreadsheet. Phones are busy in the morning, double bookings happen about once a week, and around 15% of patients miss their appointment, mostly because they forgot. Each missed slot is lost income and a patient who waited longer than necessary.

## What we want

A simple web app where patients book, move and cancel appointments themselves, and get reminders on WhatsApp, which almost all of our patients use.

### Patients

- See free slots for each doctor for the next four weeks and book one in under a minute, on a phone.
- Give their name, mobile number and a short reason for the visit. No account or password: a one-time code sent to their phone confirms the booking.
- Get a WhatsApp confirmation right away, a reminder 24 hours before, and another 2 hours before. They can reply "C" to confirm or "X" to cancel.
- Move or cancel up to 4 hours before the appointment, from a link in the reminder.

### Reception staff

- See the day's schedule per doctor, mark patients as arrived or no-show, and book walk-ins and phone bookings for patients who prefer to call.
- Block time for a doctor (holidays, training, emergencies). Patients with affected bookings get a WhatsApp message with a link to rebook.
- Export a monthly report: bookings, cancellations, no-shows per doctor.

### Doctors

- See their own schedule for the day and week, including the reason for each visit.

## Constraints

- Opening hours are Monday to Saturday, 8:00 to 18:00. Slots are 15 minutes; some visit types take two slots.
- Patient data is health data. Store as little as possible, keep it in the EU, and delete booking details 12 months after the visit unless the law requires longer.
- WhatsApp messages must use the official WhatsApp Business API with pre-approved templates. Patients must opt in, and must be able to opt out at any time.
- The clinic has no IT staff. Hosting must be managed, with backups, and cost under 100 EUR per month.
- The app must work in English and Spanish.

## Not in scope for the first version

- Payments and insurance.
- Medical records, prescriptions or test results.
- Video consultations.
- Multiple clinic locations.

## How we will know it works

- Phone bookings fall by half within three months.
- No-shows fall below 7%.
- Zero double bookings.
- Receptionists say the daily schedule view is faster than the spreadsheet.
