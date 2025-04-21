 1.Features
 Login & Register: Users log in with username and password; phone verification is required during registration.
 MFA Verification: After login, users must input a 6-digit code sent to them for additional verification.
 AI Project Scoring: Descriptions of crowdfunding projects are analyzed by an AI model to determine whether they are human-written or AI-generated, producing a trust score.
 IP Behavior Detection: If the user’s login IP differs from the previous one, the system will issue a warning of “unusual login”.
 Rate Limiting: Enforces frequency limits on login, registration, and project submission to prevent brute-force and automated attacks.
 Attack Simulation: Includes 6 test scripts to verify protection mechanisms through simulated attacks.
 2. Project Structure
 	app.py:Main application with routing and core logic.
	model/：AI model components including detector, model file, and vectorizer.
	templates/：HTML templates for login, register, query, and project creation.
	attack_scripts/：Scripts simulating different attacks like brute-force, session spoofing.
	data/：Includes datasets used for model training and testing.
  database.db: SQLite database storing user, project, and behavior records.
	requirements.txt：List of Python dependencies.
 3.Simulated Attack Types
 Brute-force: Tries multiple username-password combinations.Defense: Login limits, no code sent unless success, IP throttling.
 Code brute-force: Brute-force 6-digit code.Defense: Lockout after 3 incorrect code attempts.
 IP change: Login from a new IP with valid credentials.Defense: IP check triggers warning.
 Fake registration: Mass account creation via scripts.Defense: Unique phone validation, rate-limiting, verification codes.
 Session spoofing: Forge session to skip login.Defense: MFA-protected session enforcement.
 Project spam: Submitting spam content rapidly.Defense: Rate-limit on project submission.
