import React from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faEnvelope, faPaperPlane, faPhone } from "@fortawesome/free-solid-svg-icons";
import { faWhatsapp } from "@fortawesome/free-brands-svg-icons";
import callsvg from "../assets/contact-icons/call.svg";


const Contact = () => {
  return (
    <section id="contact" className="bg-white py-20 px-5 md:px-20">
      <div className="flex flex-col md:flex-row gap-10 items-start">
        {/* Left Section: Contact Info */}
        <div className="flex-1 text-left">
          <h4 className="text-bluePrimary font-playfair font-bold text-lg uppercase mb-2">Contact Us</h4>
          <h2 className="text-bluePrimary font-playfair text-3xl md:text-5xl font-bold mb-6">
            Get In Touch With Us
          </h2>
          <p className="text-gray-600 text-lg leading-relaxed mb-6">
            Got questions or need assistance? Our team is here to ensure your Party Currency 
            experience is smooth and enjoyable—don’t hesitate to reach out!
          </p>
          <div className="space-y-6">
            {/* Contact Methods */}
            <div className="flex items-center gap-4">
              <div className="px-1">
                <svg width="40" height="40" viewBox="0 0 70 71" fill="none" xmlns="http://www.w3.org/2000/svg">
                <rect x="1.5" y="1.5" width="68" height="68" rx="34" stroke="#6A7BA2" stroke-width="2"/>
                <path d="M44.0385 50.4997C42.7311 50.4997 40.8946 50.027 38.1445 48.4908C34.8002 46.6158 32.2136 44.8847 28.8874 41.5679C25.6805 38.3637 24.1199 36.2891 21.9358 32.3154C19.4683 27.8287 19.8889 25.4769 20.3591 24.4717C20.9191 23.2704 21.7456 22.5519 22.8139 21.8387C23.4207 21.4412 24.0628 21.1005 24.7321 20.8208C24.7991 20.792 24.8614 20.7646 24.917 20.7398C25.2485 20.5905 25.7508 20.3648 26.3871 20.6059C26.8118 20.7652 27.1909 21.0914 27.7843 21.6773C29.0013 22.8773 30.6644 25.5499 31.2779 26.8624C31.6898 27.747 31.9624 28.3309 31.9631 28.9859C31.9631 29.7526 31.5773 30.3439 31.1091 30.9821C31.0213 31.102 30.9343 31.2165 30.8499 31.3276C30.3402 31.9973 30.2283 32.1908 30.302 32.5364C30.4514 33.2308 31.5652 35.298 33.3957 37.1241C35.2262 38.9503 37.2342 39.9936 37.9315 40.1422C38.2918 40.2193 38.4894 40.1027 39.1806 39.5751C39.2797 39.4994 39.3815 39.421 39.488 39.3427C40.202 38.8117 40.766 38.436 41.5148 38.436H41.5188C42.1705 38.436 42.7284 38.7186 43.6527 39.1846C44.8583 39.7927 47.6118 41.434 48.8194 42.6521C49.4068 43.2441 49.7343 43.6218 49.8944 44.0456C50.1355 44.6838 49.9085 45.184 49.7604 45.5189C49.7357 45.5745 49.7082 45.6354 49.6794 45.703C49.3975 46.371 49.0547 47.0117 48.6553 47.6169C47.9433 48.6816 47.222 49.506 46.0177 50.0665C45.3993 50.359 44.7226 50.5071 44.0385 50.4997Z" fill="#6A7BA2"/>
                </svg>
              </div>
              <div>
                <h5 className="text-lg font-bold text-paragraph">Telephone</h5>
                <p className="text-gray-600">1 (437) 1234 74</p>
              </div>
            </div>

            <div className="flex items-center gap-4">
              <div className="px-1">
                <svg width="40" height="40" viewBox="0 0 70 71" fill="none" xmlns="http://www.w3.org/2000/svg">
                <rect x="1" y="1.5" width="68" height="68" rx="34" stroke="#6A7BA2" stroke-width="2"/>
                <path d="M47.4875 28.6838C47.4759 28.1475 47.4329 27.6124 47.3587 27.0812C47.2691 26.6088 47.1165 26.1506 46.905 25.7188C46.4425 24.8052 45.7008 24.063 44.7875 23.6C44.3584 23.3897 43.9031 23.2375 43.4338 23.1475C42.8985 23.072 42.3592 23.0282 41.8188 23.0163C41.59 23.0075 41.2937 23.0038 41.1562 23.0038L28.8463 23C28.7088 23 28.4125 23.0037 28.1838 23.0125C27.6475 23.0241 27.1124 23.0671 26.5812 23.1412C26.1088 23.2309 25.6506 23.3835 25.2188 23.595C24.3052 24.0575 23.563 24.7992 23.1 25.7125C22.8897 26.1416 22.7375 26.5969 22.6475 27.0662C22.5716 27.6015 22.5274 28.1408 22.515 28.6813C22.5075 28.91 22.5025 29.2062 22.5025 29.3438L22.5 41.6538C22.5 41.7913 22.5037 42.0875 22.5125 42.3162C22.5241 42.8525 22.5671 43.3876 22.6412 43.9188C22.7309 44.3912 22.8835 44.8494 23.095 45.2812C23.5575 46.1948 24.2992 46.937 25.2125 47.4C25.6416 47.6103 26.0969 47.7625 26.5662 47.8525C27.1015 47.928 27.6408 47.9718 28.1813 47.9837C28.41 47.9925 28.7062 47.9963 28.8438 47.9963L41.1538 47.9988C41.2913 47.9988 41.5875 47.995 41.8162 47.9862C42.3525 47.9746 42.8876 47.9316 43.4188 47.8575C43.8912 47.7679 44.3494 47.6153 44.7812 47.4038C45.6952 46.9415 46.4379 46.1997 46.9012 45.2863C47.1116 44.8571 47.2638 44.4019 47.3537 43.9325C47.4296 43.3972 47.4739 42.858 47.4862 42.3175C47.4937 42.0888 47.4988 41.7925 47.4988 41.655L47.5 29.3463C47.5 29.2088 47.4963 28.9125 47.4875 28.6838ZM35.2712 44.1963H35.2675C33.7794 44.1973 32.3149 43.8242 31.0087 43.1113L26.2838 44.35L27.5487 39.7337C26.5693 38.0341 26.178 36.0589 26.4354 34.1142C26.6928 32.1696 27.5846 30.3642 28.9725 28.9779C30.3604 27.5917 32.1668 26.702 34.1118 26.4469C36.0568 26.1918 38.0315 26.5855 39.73 27.567C41.4284 28.5484 42.7556 30.0628 43.5058 31.8753C44.256 33.6878 44.3873 35.6972 43.8792 37.5919C43.3712 39.4866 42.2523 41.1608 40.696 42.3548C39.1397 43.5489 37.2329 44.1962 35.2712 44.1963Z" fill="#6A7BA2"/>
                <path d="M35.2749 27.8762C33.9513 27.8759 32.6517 28.2301 31.5113 28.9021C30.371 29.5741 29.4315 30.5394 28.7905 31.6975C28.1496 32.8556 27.8306 34.1643 27.8668 35.4874C27.9029 36.8106 28.2929 38.0999 28.9962 39.2212L29.1724 39.5013L28.4237 42.2337L31.2274 41.4988L31.4974 41.6588C32.6384 42.3357 33.9408 42.6924 35.2674 42.6913H35.2712C37.2359 42.6916 39.1204 41.9114 40.5099 40.5223C41.8994 39.1333 42.6802 37.2491 42.6806 35.2844C42.6809 33.3196 41.9007 31.4352 40.5117 30.0457C39.1226 28.6561 37.2384 27.8753 35.2737 27.875L35.2749 27.8762ZM39.6299 38.4638C39.4663 38.7345 39.2483 38.9684 38.9897 39.1507C38.7311 39.3329 38.4375 39.4595 38.1274 39.5225C37.6595 39.6029 37.1792 39.5729 36.7249 39.435C36.2938 39.3014 35.8703 39.1445 35.4562 38.965C33.9183 38.1932 32.6076 37.0349 31.6524 35.6038C31.1312 34.9413 30.8149 34.141 30.7424 33.3012C30.7367 32.9547 30.803 32.6107 30.9373 32.2911C31.0716 31.9716 31.2708 31.6834 31.5224 31.445C31.5971 31.3604 31.6883 31.292 31.7904 31.2441C31.8925 31.1961 32.0034 31.1696 32.1162 31.1662C32.2637 31.1662 32.4124 31.1662 32.5424 31.1737C32.6799 31.18 32.8624 31.1213 33.0424 31.5563C33.2299 32.0013 33.6749 33.0975 33.7299 33.2087C33.765 33.2672 33.7851 33.3333 33.7884 33.4014C33.7916 33.4694 33.778 33.5373 33.7487 33.5988C33.6929 33.7326 33.6179 33.8577 33.5262 33.97C33.4137 34.1 33.2924 34.26 33.1924 34.36C33.0799 34.4713 32.9649 34.5912 33.0937 34.8138C33.4286 35.386 33.846 35.9057 34.3324 36.3563C34.8613 36.8252 35.4673 37.199 36.1237 37.4613C36.3462 37.5738 36.4762 37.5538 36.6062 37.405C36.7362 37.2563 37.1624 36.755 37.3112 36.5325C37.4599 36.31 37.6074 36.3475 37.8112 36.4213C38.0149 36.495 39.1112 37.0338 39.3337 37.1463C39.5562 37.2587 39.7049 37.3125 39.7599 37.405C39.82 37.7631 39.7749 38.1309 39.6299 38.4638Z" fill="#6A7BA2"/>
                </svg> 
              </div>

              <div>
                <h5 className="text-lg font-bold text-paragraph">Whatsapp</h5>
                <p className="text-gray-600">+1 (764) 3782 85</p>
              </div>
            </div>

            <div className="flex items-center gap-4">
              <div className="px-1">
                <svg width="40" height="40" viewBox="0 0 70 71" fill="none" xmlns="http://www.w3.org/2000/svg">
                <rect x="1" y="1.5" width="68" height="68" rx="34" stroke="#6A7BA2" stroke-width="2"/>
                <path d="M45 25.5H25C23.625 25.5 22.5125 26.625 22.5125 28L22.5 43C22.5 44.375 23.625 45.5 25 45.5H45C46.375 45.5 47.5 44.375 47.5 43V28C47.5 26.625 46.375 25.5 45 25.5ZM45 30.5L35 36.75L25 30.5V28L35 34.25L45 28V30.5Z" fill="#6A7BA2"/>
                </svg>
              </div>              
              <div>
                <h5 className="text-lg font-bold text-paragraph">Email Address</h5>
                <p className="text-gray-600">partycurrency@gmail.com</p>
              </div>
            </div>
          </div>
        </div>

        {/* Right Section: Contact Form */}
        <div className="flex-1 bg-bluePrimary text-white p-8 rounded-2xl">
          <form className="space-y-6">
            <div>
              <label htmlFor="fullName" className="block text-sm font-medium mb-1">
                Full Name
              </label>
              <input
                type="text"
                id="fullName"
                placeholder="Full Name"
                className="w-full p-3 rounded-lg text-gray-900"
              />
            </div>

            <div>
              <label htmlFor="emailAddress" className="block text-sm font-medium mb-1">
                Email Address
              </label>
              <input
                type="email"
                id="emailAddress"
                placeholder="Email Address"
                className="w-full p-3 rounded-lg text-gray-900"
              />
            </div>

            <div>
              <label htmlFor="telephone" className="block text-sm font-medium mb-1">
                Telephone
              </label>
              <input
                type="text"
                id="telephone"
                placeholder="Telephone"
                className="w-full p-3 rounded-lg text-gray-900"
              />
            </div>

            <div>
              <label htmlFor="message" className="block text-sm font-medium mb-1">
                Type in message...
              </label>
              <textarea
                id="message"
                placeholder="Type in message..."
                rows="5"
                className="w-full p-3 rounded-lg text-gray-900"
              />
            </div>

            <button
              type="submit"
              className="bg-gold rounded-lg hover:bg-yellow-500 
              text-lg font-medium py-3 px-6 transition-all w-full"
            >
              Send Message <FontAwesomeIcon icon={faPaperPlane} className="ml-2" />
            </button>
          </form>
        </div>
      </div>
    </section>
  );
};

export default Contact;
