using AlquilaFacilPlatform.Contacts.Domain.Model.Aggregates;
using AlquilaFacilPlatform.Shared.Infrastructure.Persistence.EFC.Configuration.Extensions;
using AlquilaFacilPlatform.Subscriptions.Domain.Model.Aggregates;
using AlquilaFacilPlatform.Subscriptions.Domain.Model.Entities;
using AlquilaFacilPlatform.IAM.Domain.Model.Aggregates;
using AlquilaFacilPlatform.IAM.Domain.Model.Entities;
using AlquilaFacilPlatform.Locals.Domain.Model.Aggregates;
using AlquilaFacilPlatform.Locals.Domain.Model.Entities;
using AlquilaFacilPlatform.Profiles.Domain.Model.Aggregates;
using EntityFrameworkCore.CreatedUpdatedDate.Extensions;
using Microsoft.EntityFrameworkCore;

namespace AlquilaFacilPlatform.Shared.Infrastructure.Persistence.EFC.Configuration;

public class AppDbContext(DbContextOptions options) : DbContext(options)
{
    protected override void OnConfiguring(DbContextOptionsBuilder builder)
    {
        base.OnConfiguring(builder);
        // Enable Audit Fields Interceptors
        builder.AddCreatedUpdatedInterceptor();
    }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        
        // Place here your entities configuration
        
        builder.Entity<Plan>().HasKey(p => p.Id);
        builder.Entity<Plan>().Property(p => p.Id).IsRequired().ValueGeneratedOnAdd();
        builder.Entity<Plan>().Property(p => p.Name).IsRequired().HasMaxLength(30);
        builder.Entity<Plan>().Property(p => p.Service).IsRequired().HasMaxLength(30);
        builder.Entity<Plan>().Property(p => p.Price).IsRequired() ;

        builder.Entity<Plan>().HasMany<Subscription>().WithOne().HasForeignKey(s => s.PlanId);
        
        builder.Entity<Subscription>().HasKey(s => s.Id);
        builder.Entity<Subscription>().Property(s => s.Id).IsRequired().ValueGeneratedOnAdd();
        builder.Entity<Subscription>().HasOne<SubscriptionStatus>().WithMany()
            .HasForeignKey(s => s.SubscriptionStatusId);
        

        builder.Entity<SubscriptionStatus>().HasKey(s => s.Id);
        builder.Entity<SubscriptionStatus>().Property(s => s.Id).IsRequired().ValueGeneratedOnAdd();
        builder.Entity<SubscriptionStatus>().Property(s => s.Status);

        builder.Entity<Invoice>().HasKey(i => i.Id);
        builder.Entity<Invoice>().Property(i => i.Id).IsRequired().ValueGeneratedOnAdd();
        builder.Entity<Invoice>().Property(i => i.SubscriptionId).IsRequired();
        builder.Entity<Invoice>().Property(i => i.Amount).IsRequired();
        builder.Entity<Invoice>().Property(i => i.Date).IsRequired();

        builder.Entity<Subscription>()
            .HasOne<Plan>().WithMany().HasForeignKey(s => s.PlanId);
        

        builder.Entity<Subscription>().HasOne<Invoice>().WithOne().HasForeignKey<Invoice>(i => i.SubscriptionId);


        builder.Entity<LocalCategory>().HasKey(c => c.Id);
        builder.Entity<LocalCategory>().Property(c => c.Id).IsRequired().ValueGeneratedOnAdd();
        builder.Entity<LocalCategory>().Property(c => c.Name).IsRequired().HasMaxLength(30);


        builder.Entity<LocalCategory>().HasMany<Local>()
            .WithOne()
            .HasForeignKey(t => t.LocalCategoryId);
        
        
        
        
        builder.Entity<Local>().HasKey(p => p.Id);
        builder.Entity<Local>().Property(p => p.Id).IsRequired().ValueGeneratedOnAdd();
        builder.Entity<Local>().OwnsOne(p => p.Price,
            n =>
            {
                n.WithOwner().HasForeignKey("Id");
                n.Property(p => p.PriceNight).HasColumnName("PriceNight");
            });
        builder.Entity<Local>().OwnsOne(p => p.LType,
            e =>
            {
                e.WithOwner().HasForeignKey("Id");
                e.Property(a => a.TypeLocal).HasColumnName("TypeLocal");
            });
        builder.Entity<Local>().OwnsOne(p => p.Address,
            a =>
            {
                a.WithOwner().HasForeignKey("Id");
                a.Property(s => s.District).HasColumnName("District");
                a.Property(s => s.Street).HasColumnName("Street");

            });
        builder.Entity<Local>().OwnsOne(p => p.Photo,
            h =>
            {
                h.WithOwner().HasForeignKey("Id");
                h.Property(g => g.PhotoUrlLink).HasColumnName("PhotoUrlLink");

            });
        builder.Entity<Local>().OwnsOne(p => p.Description,
            h =>
            {
                h.WithOwner().HasForeignKey("Id");
                h.Property(g => g.MessageDescription).HasColumnName("Description");

            });
        builder.Entity<Local>().OwnsOne(p => p.Place,
            a =>
            {
                a.WithOwner().HasForeignKey("Id");
                a.Property(s => s.Country).HasColumnName("Country");
                a.Property(s => s.City).HasColumnName("City");

            });

        builder.Entity<Local>().HasOne<User>().WithMany().HasForeignKey(l => l.UserId);
            
        // Profile Context
        
        builder.Entity<Profile>().HasKey(p => p.Id);
        builder.Entity<Profile>().Property(p => p.Id).IsRequired().ValueGeneratedOnAdd();
        builder.Entity<Profile>().OwnsOne(p => p.Name,
            n =>
            {
                n.WithOwner().HasForeignKey("Id");
                n.Property(p => p.Name).HasColumnName("FirstName");
                n.Property(p => p.FatherName).HasColumnName("FatherName");
                n.Property(p => p.MotherName).HasColumnName("MotherName");
            });
        builder.Entity<Profile>().OwnsOne(p => p.PhoneN,
            e =>
            {
                e.WithOwner().HasForeignKey("Id");
                e.Property(a => a.PhoneNumber).HasColumnName("PhoneNumber");
            });
        builder.Entity<Profile>().OwnsOne(p => p.DocumentN,
            e =>
            {
                e.WithOwner().HasForeignKey("Id");
                e.Property(a => a.NumberDocument).HasColumnName("NumberDocument");
            });
        builder.Entity<Profile>().OwnsOne(p => p.Birth,
            e =>
            {
                e.WithOwner().HasForeignKey("Id");
                e.Property(a => a.BirthDate).HasColumnName("BirthDate");
            });
        
        builder.Entity<Profile>().HasOne<User>().WithOne().HasForeignKey<Profile>(p => p.UserId);
        
        
        // Contact Context
        
        builder.Entity<Contact>().HasKey(p => p.Id);
        builder.Entity<Contact>().Property(p => p.Id).IsRequired().ValueGeneratedOnAdd();
        builder.Entity<Contact>().OwnsOne(c => c.EAdress,
            n =>
            {
                n.WithOwner().HasForeignKey("Id");
                n.Property(c => c.EmailAdress).HasColumnName("EmailAdress");
            });
        builder.Entity<Contact>().OwnsOne(p => p.CMessage,
            e =>
            {
                e.WithOwner().HasForeignKey("Id");
                e.Property(a => a.ContactMessage).HasColumnName("ContactMessage");
            });
        builder.Entity<Contact>().OwnsOne(p => p.FullName,
            a =>
            {
                a.WithOwner().HasForeignKey("Id");
                a.Property(s => s.Name).HasColumnName("Name");
                a.Property(s => s.Lastname).HasColumnName("Lastname");

            });
        builder.Entity<Contact>().OwnsOne(p => p.NPhone,
            h =>
            {
                h.WithOwner().HasForeignKey("Id");
                h.Property(g => g.PhoneNumber).HasColumnName("PhoneNumber");

            });

        builder.Entity<Contact>().HasOne<User>().WithMany().HasForeignKey(c => c.UserId);
        
        
        //IAM Context
        
        builder.Entity<User>().HasKey(u => u.Id);
        builder.Entity<User>().Property(u => u.Id).IsRequired().ValueGeneratedOnAdd();
        builder.Entity<User>().Property(u => u.Username).IsRequired();
        builder.Entity<User>().Property(u => u.PasswordHash).IsRequired();
        builder.Entity<User>().Property(u => u.Email).IsRequired();
        builder.Entity<UserRole>().HasMany<User>().WithOne().HasForeignKey(u => u.RoleId);

        builder.Entity<UserRole>().HasKey(ur => ur.Id);
        builder.Entity<UserRole>().Property(ur => ur.Id).IsRequired().ValueGeneratedOnAdd();
        builder.Entity<UserRole>().Property(ur => ur.Role).IsRequired();
        
            
        /*builder.Entity<User>()
            .HasMany(c => c.Profiles)
            .WithOne(t => t.User)
            .HasForeignKey(t => t.UserId)
            .HasPrincipalKey(t => t.Id);*/
            
        
        // Apply SnakeCase Naming Convention
        builder.UseSnakeCaseWithPluralizedTableNamingConvention();
        

    }
}