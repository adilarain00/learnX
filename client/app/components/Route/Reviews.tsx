import Client1 from "../../../public/assests/hero-banner-3.png";
import ReviewCard from "../Review/ReviewCard";
import { styles } from "@/app/styles/style";
import Image from "next/image";
import React from "react";


type Props = {};

export const reviews = [
  {
    "name": "Ethan Carter",
    "avatar": "https://randomuser.me/api/portraits/men/10.jpg",
    "profession": "Software Engineer | MIT",
    "comment": "LearnX has been a game-changer for me! The courses are well-structured, easy to follow, and packed with real-world applications. The hands-on projects helped me build a strong portfolio, which played a key role in landing my first job."
  },
  {
    "name": "Noah Bennett",
    "avatar": "https://randomuser.me/api/portraits/men/15.jpg",
    "profession": "Full Stack Developer | Stanford University",
    "comment": "The instructors at LearnX are top-notch! Their in-depth explanations and interactive content make complex topics easy to understand. The platform stands out because of its focus on real-world applications. I particularly enjoyed the project-based learning approach, which gave me confidence in building real applications. The community is also very supportive, making it easier to get help whenever needed. Highly recommended for anyone serious about learning tech skills!"
  },
  {
    "name": "Liam Hayes",
    "avatar": "https://randomuser.me/api/portraits/men/22.jpg",
    "profession": "Data Scientist | Harvard University",
    "comment": "I never thought I could master data science until I joined LearnX. The structured lessons and real-world case studies made learning fun and practical. The platform provides a fantastic blend of theory and hands-on practice, ensuring that I don’t just learn concepts but also apply them in real scenarios. The way machine learning models and algorithms are explained is truly exceptional. If you're looking to enter the world of data science, LearnX is the perfect place to start!"
  },
  {
    "name": "Mason Wright",
    "avatar": "https://randomuser.me/api/portraits/men/30.jpg",
    "profession": "Cybersecurity Analyst | UC Berkeley",
    "comment": "Security concepts always seemed intimidating to me, but LearnX simplified everything. The hands-on labs and real-world examples made all the difference. An excellent platform for tech enthusiasts!"
  },
  {
    "name": "Elijah Ford",
    "avatar": "https://randomuser.me/api/portraits/men/40.jpg",
    "profession": "AI Researcher | Oxford University",
    "comment": "LearnX doesn’t just teach theory; it ensures you apply what you learn. The AI courses were detailed and well-structured, helping me build my own projects. A must-try for tech learners!"
  },
  {
    "name": "James Sullivan",
    "avatar": "https://randomuser.me/api/portraits/men/50.jpg",
    "profession": "Freelance Web Developer",
    "comment": "I wanted to switch careers to web development, and LearnX gave me everything I needed. The practical approach and supportive community helped me gain confidence and secure freelance projects. One of the things I appreciate most is the flexibility of the courses—whether you want to learn at your own pace or follow a structured path, LearnX has you covered. I now have multiple clients thanks to the strong foundation I built here. Definitely worth it!"
  }
];

const Reviews = (props: Props) => {
  return (
    <div className="w-[90%] 800px:w-[85%] m-auto">
      <div className="w-full 800px:flex items-center">
        <div className="800px:w-[50%] w-full">
          <Image
            src={Client1}
            alt="business"
            width={500}
            height={500}
          />
        </div>
        <div className="800px:w-[50%] w-full">
          <h3 className={`${styles.title} 800px:!text-[40px]`}>
            Empowering Students Hear Their Success Stories
          </h3>
          <br />
          <p className={styles.label}>
          At <span className="text-[#9e2828]">LearnX</span>, our students are at the heart of everything we do. Their success stories, transformative learning experiences, and career growth inspire us to keep improving. With thousands of positive reviews, our learners highlight the quality of our courses, expert instructors, and the real-world skills they gain.
          </p>
        </div>
        <br />
        <br />
      </div>
      <div className="grid grid-cols-1 gap-[25px] md:grid-cols-2 md:gap-[25px] lg:grid-cols-2 lg:gap-[25px] xl:grid-cols-2 xl:gap-[35px] mb-12 border-0 md:[&>*:nth-child(3)]:!mt-[-60px] md:[&>*:nth-child(6)]:!mt-[-20px] mt-20">
        {reviews &&
          reviews.map((i, index) => <ReviewCard item={i} key={index} />)}
      </div>
    </div>
  );
};

export default Reviews;
