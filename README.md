[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]
[![MIT License][license-shield]][license-url]
[![LinkedIn][linkedin-shield]][linkedin-url]



<!-- PROJECT LOGO -->
<br />
<p align="center">
  <a href="https://github.com/aydinnyunus/PassDetective">
  </a>

<h3 align="center">PassDetective</h3>

  <p align="center">
    <br />
    <a href="https://github.com/aydinnyunus/PassDetective"><strong>Explore the docs »</strong></a>
    <br />
    <br />
    ·
    <a href="https://github.com/aydinnyunus/PassDetective/issues">Report Bug</a>
    ·
    <a href="https://github.com/aydinnyunus/PassDetective/issues">Request Feature</a>
  </p>
</p>



<!-- TABLE OF CONTENTS -->
<details open="open">
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#installation">Installation</a></li>
      </ul>
    </li>
    <li>
      <a href="#usage">Usage</a>
         <ul>
            <li><a href="#analyze-zsh">Analyze ZSH History</a></li>
            <li><a href="#analyze-bash">Analyze Bash History</a></li>
           <li><a href="#regex-scan">Regex Scan on Shell History</a></li>
         </ul>
   </li>
    <li><a href="#reports">Reports</a></li>
    <li><a href="#roadmap">Roadmap</a></li>
    <li><a href="#contributing">Contributing</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#contact">Contact</a></li>
  </ol>
</details>


<!-- GETTING STARTED -->

## Getting Started

PassDetective is a command-line tool that scans your shell command history for mistakenly written passwords, API keys, and secrets. It uses regular expressions to identify potential sensitive information and helps you avoid accidentally exposing sensitive data in your command history.


## Installation

```bash
go install github.com/aydinnyunus/PassDetective@latest
```

## Features

- Scans shell command history to detect mistakenly written passwords
- Identifies API keys and secrets using regular expressions
- Provides a secure way to review your command history and prevent accidental exposure of sensitive information

<!-- USAGE EXAMPLES -->

## Usage

![PassDetective Help](https://i.imgur.com/UeMRWTd.png)

### Extract Shell History

![Extract History](https://i.imgur.com/M1IRYt7.png)

After you have install requirements , you can simply analyze the image via:

```shell
   $ PassDetective extract -all
```

![Extract All](https://i.imgur.com/zKjs3p8.png)


### Extract Secrets

If you want to specify directory use this command:

```shell
   $ PassDetective extract --secrets --zsh
```

![Secrets](https://i.imgur.com/yw3v0RI.png)

## Regular Expressions
PassDetective uses the following regular expressions to identify potential sensitive information:

```
  "Cloudinary"  : "cloudinary://.*",
  "Firebase URL": ".*firebaseio\.com",
  "Slack Token": "(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})",
  "RSA private key": "-----BEGIN RSA PRIVATE KEY-----",
  "SSH (DSA) private key": "-----BEGIN DSA PRIVATE KEY-----",
  "SSH (EC) private key": "-----BEGIN EC PRIVATE KEY-----",
  "PGP private key block": "-----BEGIN PGP PRIVATE KEY BLOCK-----",
  "Amazon AWS Access Key ID": "AKIA[0-9A-Z]{16}",
  "Amazon MWS Auth Token": "amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
  "AWS API Key": "AKIA[0-9A-Z]{16}",
  "Facebook Access Token": "EAACEdEose0cBA[0-9A-Za-z]+",
  "Facebook OAuth": "[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].*['|\"][0-9a-f]{32}['|\"]",
  "GitHub": "[g|G][i|I][t|T][h|H][u|U][b|B].*['|\"][0-9a-zA-Z]{35,40}['|\"]",
  "Generic API Key": "[a|A][p|P][i|I][_]?[k|K][e|E][y|Y].*['|\"][0-9a-zA-Z]{32,45}['|\"]",
  "Generic Secret": "[s|S][e|E][c|C][r|R][e|E][t|T].*['|\"][0-9a-zA-Z]{32,45}['|\"]",
  "Google API Key": "AIza[0-9A-Za-z\\-_]{35}",
  "Google Cloud Platform API Key": "AIza[0-9A-Za-z\\-_]{35}",
  "Google Cloud Platform OAuth": "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
  "Google Drive API Key": "AIza[0-9A-Za-z\\-_]{35}",
  "Google Drive OAuth": "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
  "Google (GCP) Service-account": "\"type\": \"service_account\"",
  "Google Gmail API Key": "AIza[0-9A-Za-z\\-_]{35}",
  "Google Gmail OAuth": "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
  "Google OAuth Access Token": "ya29\\.[0-9A-Za-z\\-_]+",
  "Google YouTube API Key": "AIza[0-9A-Za-z\\-_]{35}",
  "Google YouTube OAuth": "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
  "Heroku API Key": "[h|H][e|E][r|R][o|O][k|K][u|U].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
  "MailChimp API Key": "[0-9a-f]{32}-us[0-9]{1,2}",
  "Mailgun API Key": "key-[0-9a-zA-Z]{32}",
  "Password in URL": "[a-zA-Z]{3,10}://[^/\\s:@]{3,20}:[^/\\s:@]{3,20}@.{1,100}[\"'\\s]",
  "PayPal Braintree Access Token": "access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}",
  "Picatic API Key": "sk_live_[0-9a-z]{32}",
  "Slack Webhook": "https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
  "Stripe API Key": "sk_live_[0-9a-zA-Z]{24}",
  "Stripe Restricted API Key": "rk_live_[0-9a-zA-Z]{24}",
  "Square Access Token": "sq0atp-[0-9A-Za-z\\-_]{22}",
  "Square OAuth Secret": "sq0csp-[0-9A-Za-z\\-_]{43}",
  "Twilio API Key": "SK[0-9a-fA-F]{32}",
  "Twitter Access Token": "[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*[1-9][0-9]+-[0-9a-zA-Z]{40}",
  "Twitter OAuth": "[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*['|\"][0-9a-zA-Z]{35,44}['|\"]"

```

**Source** : https://github.com/h33tlit/secret-regex-list

## Roadmap

See the [open issues](https://github.com/aydinnyunus/PassDetective/issues) for a list of proposed features (and known issues).



<!-- CONTRIBUTING -->

## Contributing

Contributions are what makes the open source community such an amazing place to learn, inspire, and create. Any
contributions you make are **greatly appreciated**.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

<!-- LICENSE -->

## License

Distributed under the Apache License 2.0 License. See `LICENSE` for more information.



<!-- CONTACT -->

## Contact

[<img target="_blank" src="https://img.icons8.com/bubbles/100/000000/linkedin.png" title="LinkedIn">](https://linkedin.com/in/yunus-ayd%C4%B1n-b9b01a18a/) [<img target="_blank" src="https://img.icons8.com/bubbles/100/000000/github.png" title="Github">](https://github.com/aydinnyunus/) [<img target="_blank" src="https://img.icons8.com/bubbles/100/000000/instagram-new.png" title="Instagram">](https://instagram.com/aydinyunus_/) [<img target="_blank" src="https://img.icons8.com/bubbles/100/000000/twitter-squared.png" title="LinkedIn">](https://twitter.com/aydinnyunuss)

<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->

[contributors-shield]: https://img.shields.io/github/contributors/usestrix/cli.svg?style=for-the-badge

[contributors-url]: https://github.com/aydinnyunus/PassDetective/graphs/contributors

[forks-shield]: https://img.shields.io/github/forks/usestrix/cli.svg?style=for-the-badge

[forks-url]: https://github.com/aydinnyunus/PassDetective/network/members

[stars-shield]: https://img.shields.io/github/stars/usestrix/cli?style=for-the-badge

[stars-url]: https://github.com/aydinnyunus/PassDetective/stargazers

[issues-shield]: https://img.shields.io/github/issues/usestrix/cli.svg?style=for-the-badge

[issues-url]: https://github.com/aydinnyunus/PassDetective/issues

[license-shield]: https://img.shields.io/github/license/usestrix/cli.svg?style=for-the-badge

[license-url]: https://github.com/aydinnyunus/PassDetective/blob/master/LICENSE.txt

[linkedin-shield]: https://img.shields.io/badge/-LinkedIn-black.svg?style=for-the-badge&logo=linkedin&colorB=555

[linkedin-url]: https://linkedin.com/in/aydinnyunus

[product-screenshot]: data/images/base_command.png

[latest-release]: https://github.com/aydinnyunus/PassDetective/releases
